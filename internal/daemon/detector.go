package daemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// Built-in LLM endpoint allowlist. YAML config adds to this — never replaces.
// Why baked-in: most users will run agentscope without a config and the
// commercial APIs below are stable enough that the daemon should detect
// them out of the box.
var (
	builtinHostnames = []string{
		"api.openai.com",
		"api.anthropic.com",
		"generativelanguage.googleapis.com",
		"api.mistral.ai",
		"api.cohere.ai",
		"api.groq.com",
	}

	builtinHostnamePatterns = []string{
		"*.openai.azure.com",
		"bedrock-runtime.*.amazonaws.com",
	}

	// Path patterns for self-hosted LLMs (vLLM, Ollama, LiteLLM, llama.cpp,
	// TGI, etc.) where SNI tells us nothing useful (private IPs, no TLS).
	builtinHTTPPaths = []string{
		"POST /v1/chat/completions",
		"POST /v1/messages",
		"POST /v1/completions",
		"POST /api/generate",
		"POST /api/chat",
	}
)

type httpPathRule struct {
	method string
	prefix string
}

type DetectorRules struct {
	Hostnames        map[string]struct{}
	HostnamePatterns []*regexp.Regexp
	HTTPPaths        []httpPathRule
}

func LoadDetectorRules(configPath string) (*DetectorRules, error) {
	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	var extraHosts, extraPatterns, extraPaths []string
	if cfg != nil {
		extraHosts = cfg.LLMHostnames
		extraPatterns = cfg.LLMHostnamePatterns
		extraPaths = cfg.LLMHTTPPaths
	}
	return BuildDetectorRules(extraHosts, extraPatterns, extraPaths)
}

func BuildDetectorRules(extraHosts, extraPatterns, extraPaths []string) (*DetectorRules, error) {
	r := &DetectorRules{Hostnames: map[string]struct{}{}}
	for _, h := range builtinHostnames {
		r.Hostnames[strings.ToLower(h)] = struct{}{}
	}
	for _, h := range extraHosts {
		r.Hostnames[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	for _, p := range append(append([]string{}, builtinHostnamePatterns...), extraPatterns...) {
		re, err := compileGlob(p)
		if err != nil {
			return nil, fmt.Errorf("hostname pattern %q: %w", p, err)
		}
		r.HostnamePatterns = append(r.HostnamePatterns, re)
	}
	for _, p := range append(append([]string{}, builtinHTTPPaths...), extraPaths...) {
		rule, err := parseHTTPPathRule(p)
		if err != nil {
			return nil, err
		}
		r.HTTPPaths = append(r.HTTPPaths, rule)
	}
	return r, nil
}

// compileGlob converts a hostname glob ('*' = one DNS label, no dots) into
// an anchored regex. Only '*' is special; everything else is literal.
func compileGlob(g string) (*regexp.Regexp, error) {
	parts := strings.Split(g, "*")
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	return regexp.Compile("^" + strings.Join(parts, "[^.]*") + "$")
}

func parseHTTPPathRule(spec string) (httpPathRule, error) {
	parts := strings.SplitN(strings.TrimSpace(spec), " ", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return httpPathRule{}, fmt.Errorf("http path rule %q: expected '<METHOD> <path>'", spec)
	}
	return httpPathRule{
		method: strings.ToUpper(strings.TrimSpace(parts[0])),
		prefix: strings.TrimSpace(parts[1]),
	}, nil
}

func (r *DetectorRules) matchHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	if _, ok := r.Hostnames[host]; ok {
		return true
	}
	for _, re := range r.HostnamePatterns {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func (r *DetectorRules) matchHTTP(method, path string) bool {
	method = strings.ToUpper(method)
	for _, rule := range r.HTTPPaths {
		if rule.method == method && strings.HasPrefix(path, rule.prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Detector: consumes SOURCE_CANDIDATE events, promotes matching PIDs into
// the agent_pids BPF map, evicts dead PIDs, expires unmatched candidates.
// ---------------------------------------------------------------------------

// PID lifecycle in the detector:
//
//	┌──────────┐  endpoint match   ┌────────────┐  agent signal  ┌───────────┐
//	│ pending  │ ────────────────▶ │ confirming │ ─────────────▶ │ confirmed │
//	└──────────┘                   └────────────┘                └───────────┘
//	      │                              │
//	      │ TTL                          │ window timeout / no signal
//	      ▼                              ▼
//	  (forgotten)                   ┌─────────┐
//	                                │ demoted │  ← never re-promoted while alive
//	                                └─────────┘
//
// "Talks to LLM API" promotes only into `confirming` — full capture starts so
// we can observe one of the agent signals (tools/functions in request body,
// tool_calls/tool_use in response, MCP, A2A traffic). If none appears within
// the window, the PID is demoted: chat WebUIs, one-shot scripts, and other
// "just hits the LLM API" callers land here and stop consuming capacity.
type detector struct {
	rules       *DetectorRules
	agentMap    *ebpf.Map
	parser      *parser
	cmdlineMust []byte
	ttl         time.Duration

	confirmWindow    time.Duration
	confirmMaxEvents int

	mu         sync.Mutex
	pending    map[uint32]time.Time     // unmatched candidates (TTL bookkeeping)
	confirming map[uint32]*confirmState // promoted, awaiting agent signal
	confirmed  map[uint32]struct{}      // permanent agents
	demoted    map[uint32]struct{}      // PIDs that lost the bet — keep out
}

type confirmState struct {
	promotedAt time.Time
	seenEvents int
	reason     string // why we promoted (for the demote-log line)
}

func newDetector(rules *DetectorRules, agentMap *ebpf.Map, parser *parser, cmdlineFilter string, ttl time.Duration) *detector {
	var must []byte
	if cmdlineFilter != "" {
		must = []byte(cmdlineFilter)
	}
	return &detector{
		rules:            rules,
		agentMap:         agentMap,
		parser:           parser,
		cmdlineMust:      must,
		ttl:              ttl,
		confirmWindow:    60 * time.Second,
		confirmMaxEvents: 8,
		pending:          map[uint32]time.Time{},
		confirming:       map[uint32]*confirmState{},
		confirmed:        map[uint32]struct{}{},
		demoted:          map[uint32]struct{}{},
	}
}

// handle processes a SOURCE_CANDIDATE event. Cheap fast-paths short-circuit
// when the PID is already classified, so it's safe to invoke inline from the
// ringbuf reader.
func (d *detector) handle(ev RawEvent) {
	d.mu.Lock()
	if _, ok := d.confirmed[ev.PID]; ok {
		d.mu.Unlock()
		return
	}
	if _, ok := d.confirming[ev.PID]; ok {
		d.mu.Unlock()
		return
	}
	if _, ok := d.demoted[ev.PID]; ok {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	matched := false
	var reason, hostShown string
	switch ev.Dir {
	case 2: // TLS hint
		sni := extractSNI(ev.Data)
		hostShown = sni
		if sni != "" && d.rules.matchHost(sni) {
			matched = true
			reason = "TLS SNI"
		}
	case 1: // HTTP hint
		method, path, host := parseHTTPMeta(ev.Data)
		hostShown = host
		if d.rules.matchHost(host) {
			matched = true
			reason = "HTTP Host"
		} else if d.rules.matchHTTP(method, path) {
			matched = true
			reason = fmt.Sprintf("HTTP path %s %s", method, path)
		}
	}

	if !matched {
		d.mu.Lock()
		d.pending[ev.PID] = time.Now()
		d.mu.Unlock()
		return
	}

	if d.cmdlineMust != nil && !pidCmdlineContains(ev.PID, d.cmdlineMust) {
		d.mu.Lock()
		d.pending[ev.PID] = time.Now()
		d.mu.Unlock()
		return
	}

	if err := d.agentMap.Put(ev.PID, uint8(1)); err != nil {
		log.Printf("detector: promote pid=%d failed: %v", ev.PID, err)
		return
	}
	d.mu.Lock()
	d.confirming[ev.PID] = &confirmState{
		promotedAt: time.Now(),
		reason:     fmt.Sprintf("%s=%s", reason, hostShown),
	}
	delete(d.pending, ev.PID)
	d.mu.Unlock()
	log.Printf("detector: provisional promote pid=%d (%s=%s, dst=%s) — awaiting agent signal",
		ev.PID, reason, hostShown, formatDst(ev.DstIP, ev.DstPort))
}

// observeEvent inspects every parser-emitted AgentEvent. While a PID is in
// the confirming state we look for an agent signal (tools/functions in the
// request, tool_calls/tool_use in the response, or a CommType marking
// Agent↔MCP / Agent↔Agent traffic). One match → confirm. None within the
// window → demote. PIDs already confirmed or demoted bypass the work.
func (d *detector) observeEvent(ev *AgentEvent) {
	if ev == nil {
		return
	}
	d.mu.Lock()
	if _, ok := d.confirmed[ev.PID]; ok {
		d.mu.Unlock()
		return
	}
	st, ok := d.confirming[ev.PID]
	if !ok {
		d.mu.Unlock()
		return
	}
	st.seenEvents++
	d.mu.Unlock()

	if hasAgentSignal(ev) {
		d.confirm(ev.PID, classifySignal(ev))
		return
	}
	if st.seenEvents >= d.confirmMaxEvents {
		d.demote(ev.PID, fmt.Sprintf("no agent signal in %d events", st.seenEvents))
	}
}

func (d *detector) confirm(pid uint32, signal string) {
	d.mu.Lock()
	st, ok := d.confirming[pid]
	if !ok {
		d.mu.Unlock()
		return
	}
	d.confirmed[pid] = struct{}{}
	delete(d.confirming, pid)
	d.mu.Unlock()
	log.Printf("detector: confirmed pid=%d (%s, originally promoted on %s)",
		pid, signal, st.reason)
}

func (d *detector) demote(pid uint32, reason string) {
	d.mu.Lock()
	if _, ok := d.confirming[pid]; !ok {
		d.mu.Unlock()
		return
	}
	delete(d.confirming, pid)
	d.demoted[pid] = struct{}{}
	d.mu.Unlock()
	if err := d.agentMap.Delete(pid); err != nil {
		log.Printf("detector: demote pid=%d agent_pids delete: %v", pid, err)
	}
	if d.parser != nil {
		d.parser.evictPID(pid)
	}
	log.Printf("detector: demoted pid=%d (%s) — likely WebUI/one-shot script",
		pid, reason)
}

// hasAgentSignal returns true if ev exhibits any of the agent-specific
// patterns. CommType captures MCP and A2A flows already classified by the
// parser; the body checks catch tool-using ReAct-style agents over plain
// LLM endpoints (no MCP, no A2A).
func hasAgentSignal(ev *AgentEvent) bool {
	if ev.CommType == "Agent↔MCP" || ev.CommType == "Agent↔Agent" {
		return true
	}
	return hasToolKeyword(ev.Request) || hasToolKeyword(ev.Response)
}

func classifySignal(ev *AgentEvent) string {
	switch ev.CommType {
	case "Agent↔MCP":
		return "MCP traffic"
	case "Agent↔Agent":
		return "A2A traffic"
	}
	if hasToolKeyword(ev.Request) {
		return "tools/functions in request body"
	}
	return "tool_calls/tool_use in response body"
}

// hasToolKeyword does a substring scan on the JSON-encoded request/response
// strings. JSON keys are quoted, so we can match the literal `"tools":` form
// without false positives from arbitrary text inside content fields.
func hasToolKeyword(jsonStr string) bool {
	if jsonStr == "" {
		return false
	}
	for _, k := range []string{`"tools":`, `"functions":`, `"tool_calls":`, `"tool_use"`} {
		if strings.Contains(jsonStr, k) {
			return true
		}
	}
	return false
}

// runJanitor evicts dead promoted PIDs and TTL-expires unmatched candidates.
// 30s tick: fast enough for a snappy demo, slow enough to be invisible in
// CPU profiles.
func (d *detector) runJanitor(stop <-chan struct{}) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			d.prune()
		}
	}
}

func (d *detector) prune() {
	now := time.Now()
	candidateCutoff := now.Add(-d.ttl)
	confirmCutoff := now.Add(-d.confirmWindow)

	d.mu.Lock()
	expired := 0
	for pid, ts := range d.pending {
		if ts.Before(candidateCutoff) {
			delete(d.pending, pid)
			expired++
		}
	}

	// PIDs in confirming state past the time window without an agent signal
	// are demoted via the same path as the event-count trigger.
	var timedOut []uint32
	for pid, st := range d.confirming {
		if st.promotedAt.Before(confirmCutoff) {
			timedOut = append(timedOut, pid)
		}
	}

	// Dead PIDs leak across all four sets; reap them so the maps stay bounded.
	var deadActive, deadDemoted []uint32
	for pid := range d.confirming {
		if !pidAlive(pid) {
			deadActive = append(deadActive, pid)
		}
	}
	for pid := range d.confirmed {
		if !pidAlive(pid) {
			deadActive = append(deadActive, pid)
		}
	}
	for pid := range d.demoted {
		if !pidAlive(pid) {
			deadDemoted = append(deadDemoted, pid)
		}
	}
	d.mu.Unlock()

	for _, pid := range timedOut {
		d.demote(pid, fmt.Sprintf("no agent signal in %s", d.confirmWindow))
	}

	for _, pid := range deadActive {
		_ = d.agentMap.Delete(pid)
		d.mu.Lock()
		delete(d.confirming, pid)
		delete(d.confirmed, pid)
		d.mu.Unlock()
		if d.parser != nil {
			d.parser.evictPID(pid)
		}
	}
	for _, pid := range deadDemoted {
		d.mu.Lock()
		delete(d.demoted, pid)
		d.mu.Unlock()
	}

	if expired > 0 || len(timedOut) > 0 || len(deadActive) > 0 || len(deadDemoted) > 0 {
		d.mu.Lock()
		log.Printf("detector: janitor pending-expired=%d window-demoted=%d dead-active=%d dead-demoted=%d (now: pending=%d confirming=%d confirmed=%d demoted=%d)",
			expired, len(timedOut), len(deadActive), len(deadDemoted),
			len(d.pending), len(d.confirming), len(d.confirmed), len(d.demoted))
		d.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

// extractSNI parses a TLS ClientHello and returns the server_name (host_name
// type) extension value, or "" on any malformed/truncated input. All reads
// are bounds-checked. Spec: RFC 6066 §3 + RFC 8446 §4.2.
func extractSNI(data []byte) string {
	// TLS Record:  type(1) version(2) length(2) = 5 bytes
	// Handshake:   type(1) length(3)            = 4 bytes
	// ClientHello: legacy_version(2) random(32) = 34 bytes
	// → 43 bytes minimum before session_id.
	if len(data) < 43 {
		return ""
	}
	if data[0] != 0x16 || data[5] != 0x01 {
		return ""
	}
	pos := 43

	// session_id
	if pos+1 > len(data) {
		return ""
	}
	sidLen := int(data[pos])
	pos += 1 + sidLen

	// cipher_suites
	if pos+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + csLen

	// compression_methods
	if pos+1 > len(data) {
		return ""
	}
	cmLen := int(data[pos])
	pos += 1 + cmLen

	// extensions
	if pos+2 > len(data) {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		extEnd := pos + extDataLen
		if extEnd > end {
			return ""
		}
		if extType == 0x0000 {
			// SNI: server_name_list_length(2) then entries.
			ePos := pos
			if ePos+2 > extEnd {
				return ""
			}
			ePos += 2
			for ePos+3 <= extEnd {
				nameType := data[ePos]
				nameLen := int(binary.BigEndian.Uint16(data[ePos+1 : ePos+3]))
				ePos += 3
				if ePos+nameLen > extEnd {
					return ""
				}
				if nameType == 0x00 {
					return string(data[ePos : ePos+nameLen])
				}
				ePos += nameLen
			}
		}
		pos = extEnd
	}
	return ""
}

// parseHTTPMeta extracts the request line (method, path) and Host: header
// from a partial HTTP/1.1 request. Returns zero values if any required field
// can't be found in the input window.
func parseHTTPMeta(data []byte) (method, path, host string) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return
	}
	first := bytes.TrimRight(data[:nl], "\r")
	parts := bytes.SplitN(first, []byte(" "), 3)
	if len(parts) < 2 {
		return
	}
	method = string(parts[0])
	path = string(parts[1])

	rest := data[nl+1:]
	if eod := bytes.Index(rest, []byte("\r\n\r\n")); eod >= 0 {
		rest = rest[:eod]
	}
	for _, line := range bytes.Split(rest, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		if strings.EqualFold(string(line[:colon]), "host") {
			host = strings.TrimSpace(string(line[colon+1:]))
			break
		}
	}
	return
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func pidAlive(pid uint32) bool {
	_, err := os.Stat("/proc/" + strconv.FormatUint(uint64(pid), 10))
	return err == nil
}

func pidCmdlineContains(pid uint32, needle []byte) bool {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")
	if err != nil {
		return false
	}
	return bytes.Contains(b, needle)
}

// formatDst renders the BPF event's __be32 dst_ip and __be16 dst_port (read
// raw, host byte order = little-endian on x86) as a familiar 1.2.3.4:port.
func formatDst(ip uint32, port uint16) string {
	a := byte(ip)
	b := byte(ip >> 8)
	c := byte(ip >> 16)
	d := byte(ip >> 24)
	hostPort := (port&0xff)<<8 | (port >> 8)
	return fmt.Sprintf("%d.%d.%d.%d:%d", a, b, c, d, hostPort)
}
