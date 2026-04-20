package daemon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AgentEvent struct {
	Host        string
	PID         uint32
	Timestamp   float64
	Direction   string
	CommType    string
	ContentType string
	Peer        string
	Request     string
	Response    string
	LatencyMs   float64
}

type connKey struct {
	Host   string
	PID    uint32
	Conn   uint64 // SSL* (TLS) or struct sock* (PLAIN) — separates concurrent conns
	Source uint8  // mirrors RawEvent.Source: TLS and PLAIN flows live in disjoint buckets
}

var llmHosts = map[string]bool{
	"api.openai.com":                    true,
	"api.anthropic.com":                 true,
	"generativelanguage.googleapis.com": true,
	"api.groq.com":                      true,
	"api.mistral.ai":                    true,
}

type parser struct {
	mu       sync.Mutex
	writeBuf map[connKey][]byte
	readBuf  map[connKey][]byte
	reqTime  map[connKey]time.Time
	lastReq  map[connKey]*http.Request
	h2       map[connKey]*h2Conn
	proto    map[connKey]byte // 0 = unknown, 1 = http/1, 2 = http/2
	hostname string

	// sseEmittedBytes[key] tracks how many bytes of the SSE response stream
	// we've already converted into per-frame events. Required because SSE
	// streams (MCP `GET /sse`, LLM streaming) can stay open for minutes —
	// we must emit each pushed `data: {...}` frame as it arrives rather
	// than wait for stream close.
	sseEmittedBytes map[connKey]int

	// mcpPending pairs MCP `POST /messages/` JSON-RPC requests (which only
	// receive a `202 Accepted` body) with their eventual result pushed on
	// the paired GET /sse stream by the server. Keyed by PID (SSE stream
	// and POST run on different SSL connections, same process) → jsonrpc
	// request id → buffered request metadata.
	mcpPending map[uint32]map[float64]*pendingMCPPost

	// emit is called for side-channel events: per-SSE-frame MCP responses,
	// paired POST/SSE combined events. The primary feed() return value is
	// used for normal HTTP/1.1 request-response pairs.
	emit func(*AgentEvent)

	// llmEndpoints / mcpEndpoints remember peers (host:port) after a
	// protocol-specific signature is observed. Once tagged, subsequent
	// calls to the same peer are classified in O(1) without re-inspecting
	// the body. Intentionally *not* tied to PID lifecycle: endpoints are
	// long-lived host/port pairs that outlive any one agent.
	//
	// llmEndpoints is populated by response-shape detection (OpenAI-compat,
	// Anthropic, Ollama, Gemini native). This covers self-hosted LLMs
	// (vLLM, Ollama, LiteLLM proxy) whose hostnames aren't in llmHosts.
	//
	// mcpEndpoints is populated by the MCP `initialize` handshake
	// (`params.protocolVersion`), or by the MCP method namespace fallback
	// (tools/*, resources/*, prompts/*) when the daemon joins mid-session.
	llmEndpoints map[string]struct{}
	mcpEndpoints map[string]struct{}

	// configPeers is a read-only map of user-declared comm-type overrides
	// loaded from the YAML config + `-peer` CLI flags. Consulted *before*
	// any heuristic in classifyComm, so operators can force-tag endpoints
	// the automatic detection gets wrong or can't yet recognise.
	configPeers map[string]string
}

// pendingMCPPost is a POST /messages/ request buffered while we wait for
// the server to push its JSON-RPC response on the paired SSE stream.
type pendingMCPPost struct {
	req      *http.Request
	method   string
	toolName string // only set for tools/call — name of the invoked tool
	arguments any
	peer     string
	reqTime  time.Time
}

const (
	maxLLMEndpoints = 1024
	maxMCPEndpoints = 1024
)

// evictPID removes every connKey entry tied to pid across all buffer maps.
// Called by the PID scanner when a tracked agent process exits — otherwise
// long-running daemons would slowly accumulate dead-PID buffers.
func (p *parser) evictPID(pid uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	evicted := 0
	evict := func(m map[connKey][]byte) {
		for k := range m {
			if k.PID == pid {
				delete(m, k)
				evicted++
			}
		}
	}
	evict(p.writeBuf)
	evict(p.readBuf)
	for k := range p.reqTime {
		if k.PID == pid {
			delete(p.reqTime, k)
			evicted++
		}
	}
	for k := range p.lastReq {
		if k.PID == pid {
			delete(p.lastReq, k)
			evicted++
		}
	}
	for k := range p.h2 {
		if k.PID == pid {
			delete(p.h2, k)
			evicted++
		}
	}
	for k := range p.proto {
		if k.PID == pid {
			delete(p.proto, k)
			evicted++
		}
	}
	for k := range p.sseEmittedBytes {
		if k.PID == pid {
			delete(p.sseEmittedBytes, k)
			evicted++
		}
	}
	if _, ok := p.mcpPending[pid]; ok {
		delete(p.mcpPending, pid)
		evicted++
	}
	if evicted > 0 {
		log.Printf("parser: evicted %d map entries for dead pid=%d", evicted, pid)
	}
}

func newParser(hostname string, configPeers map[string]string) *parser {
	if configPeers == nil {
		configPeers = map[string]string{}
	}
	return &parser{
		writeBuf:     make(map[connKey][]byte),
		readBuf:      make(map[connKey][]byte),
		reqTime:      make(map[connKey]time.Time),
		lastReq:      make(map[connKey]*http.Request),
		sseEmittedBytes: make(map[connKey]int),
		mcpPending:   make(map[uint32]map[float64]*pendingMCPPost),
		h2:           make(map[connKey]*h2Conn),
		proto:        make(map[connKey]byte),
		hostname:     hostname,
		llmEndpoints: make(map[string]struct{}),
		mcpEndpoints: make(map[string]struct{}),
		configPeers:  configPeers,
	}
}

func (p *parser) feed(raw RawEvent) *AgentEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := connKey{Host: p.hostname, PID: raw.PID, Conn: raw.Conn, Source: raw.Source}

	// Protocol detection on first meaningful write. HTTP/2 connection always
	// starts with the 24-byte preface.
	if p.proto[key] == 0 && raw.Dir == 0 {
		if looksLikeH2Preface(raw.Data) {
			p.proto[key] = 2
			p.h2[key] = newH2Conn(p.configPeers, p.llmEndpoints, p.mcpEndpoints)
		} else if looksLikeHTTP(raw.Data) {
			p.proto[key] = 1
		}
	}

	if p.proto[key] == 2 {
		c := p.h2[key]
		if c == nil {
			return nil
		}
		return c.feed(raw.Dir == 0, raw.Data, "", p.hostname, raw.PID)
	}

	// Skip events whose payload is clearly not HTTP plaintext (TLS handshake
	// artifacts, zero-filled reads after TLS session tickets, etc.).
	if !looksLikeHTTP(raw.Data) && len(p.writeBuf[key]) == 0 && len(p.readBuf[key]) == 0 {
		return nil
	}

	switch raw.Dir {
	case 0: // DIR_WRITE → send
		p.writeBuf[key] = append(p.writeBuf[key], raw.Data...)
		p.writeBuf[key] = trimToHTTPRequest(p.writeBuf[key])
		if !requestComplete(p.writeBuf[key]) {
			return nil
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p.writeBuf[key])))
		if err != nil {
			return nil
		}

		// MCP-over-SSE pairing: a POST /messages/ carries a JSON-RPC
		// request whose response is pushed on the paired GET /sse stream
		// (a different SSL connection, same PID). Buffer the POST by
		// its jsonrpc id, emit when the SSE-side response arrives.
		if bufferedBody, id, method, args, isRPC := p.tryBufferMCPPost(key, req); isRPC {
			_ = bufferedBody
			_ = id
			_ = method
			_ = args
			p.writeBuf[key] = nil
			p.readBuf[key] = nil
			p.lastReq[key] = nil
			return nil
		}

		p.lastReq[key] = req
		p.reqTime[key] = time.Now()
		p.writeBuf[key] = nil
		p.readBuf[key] = nil // 새 요청 시작 시 이전 read 버퍼 초기화

	case 1: // DIR_READ → recv 완성
		req := p.lastReq[key]
		if req == nil {
			return nil // TLS 핸드셰이크 등 요청 전 read는 무시
		}
		p.readBuf[key] = append(p.readBuf[key], raw.Data...)
		p.readBuf[key] = trimToHTTPResponse(p.readBuf[key])

		// SSE streaming: emit each pushed frame as its own MCP event
		// (side effect inside maybeEmitSSEFrames) — but still fall through
		// to the normal completion path. MCP streams stay open forever and
		// never reach responseComplete=true; LLM streams terminate with
		// `data: [DONE]` so responseComplete fires and buildEvent merges
		// the per-chunk text into the final summary.
		p.maybeEmitSSEFrames(key, req)

		if !responseComplete(p.readBuf[key]) {
			return nil
		}
		res, err := http.ReadResponse(
			bufio.NewReader(bytes.NewReader(p.readBuf[key])), req,
		)
		if err != nil {
			return nil
		}
		event := p.buildEvent(key, req, res)
		p.readBuf[key] = nil
		p.lastReq[key] = nil
		delete(p.sseEmittedBytes, key)
		return event
	}
	return nil
}

// tryBufferMCPPost inspects a newly-parsed request. If it is a POST
// /messages/ carrying an MCP JSON-RPC request with an `id` (i.e. expects
// a response pushed via SSE), it is buffered by PID+id for later pairing
// and (true, ...) is returned. Notifications (method but no id) and
// non-MCP requests are left to normal flow.
func (p *parser) tryBufferMCPPost(key connKey, req *http.Request) ([]byte, float64, string, any, bool) {
	if req.Method != "POST" {
		return nil, 0, "", nil, false
	}
	if !strings.Contains(req.URL.Path, "/messages") {
		return nil, 0, "", nil, false
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, 0, "", nil, false
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	var j map[string]any
	if json.Unmarshal(body, &j) != nil {
		return nil, 0, "", nil, false
	}
	if j["jsonrpc"] != "2.0" {
		return nil, 0, "", nil, false
	}
	method, _ := j["method"].(string)
	if method == "" {
		return nil, 0, "", nil, false
	}
	idV, hasID := j["id"]
	if !hasID { // notification (no response expected)
		return nil, 0, "", nil, false
	}
	id, ok := idV.(float64)
	if !ok {
		return nil, 0, "", nil, false
	}
	var args any
	var toolName string
	if params, ok := j["params"].(map[string]any); ok {
		toolName, _ = params["name"].(string)
		if a, ok := params["arguments"]; ok {
			args = a
		} else if toolName == "" {
			args = params
		}
	}
	if _, ok := p.mcpPending[key.PID]; !ok {
		p.mcpPending[key.PID] = make(map[float64]*pendingMCPPost)
	}
	p.mcpPending[key.PID][id] = &pendingMCPPost{
		req:       req,
		method:    method,
		toolName:  toolName,
		arguments: args,
		peer:      req.Host,
		reqTime:   time.Now(),
	}
	return body, id, method, args, true
}

// maybeEmitSSEFrames processes new bytes in readBuf for an SSE response.
// When the response is text/event-stream it emits one AgentEvent per
// complete `data: {...}` frame (pairing MCP JSON-RPC results with their
// buffered POST request, or emitting standalone events otherwise).
// Returns true if this read was handled as an SSE stream — caller should
// NOT fall through to the normal responseComplete path.
func (p *parser) maybeEmitSSEFrames(key connKey, req *http.Request) bool {
	// Need headers before we can classify as SSE.
	headerEnd := bytes.Index(p.readBuf[key], []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}
	head := bytes.ToLower(p.readBuf[key][:headerEnd])
	if !bytes.Contains(head, []byte("content-type: text/event-stream")) {
		return false
	}

	bodyStart := headerEnd + 4
	// Decode chunked transfer encoding (MCP FastMCP uses it by default).
	body := p.readBuf[key][bodyStart:]
	if bytes.Contains(head, []byte("\r\ntransfer-encoding: chunked")) {
		body = unchunk(body)
	}

	// Normalize CRLF → LF so frame boundary detection only has to look for
	// "\n\n". SSE streams on the wire use CRLF; this is robust either way.
	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))

	// Process frames past the last emitted offset. Frames terminate on
	// double-newline. Keep already-emitted frames' byte positions via
	// sseEmittedBytes.
	already := p.sseEmittedBytes[key]
	if already > len(body) {
		already = 0 // buffer was trimmed
	}
	remainder := body[already:]
	const sep = "\n\n"
	var consumedLen int
	for {
		idx := bytes.Index(remainder[consumedLen:], []byte(sep))
		if idx < 0 {
			break
		}
		frame := remainder[consumedLen : consumedLen+idx]
		p.emitSSEFrame(key, req, frame)
		consumedLen += idx + len(sep)
	}
	p.sseEmittedBytes[key] = already + consumedLen
	return true
}

// emitSSEFrame turns one SSE frame into an AgentEvent. Frame shape:
//	event: message
//	data: {"jsonrpc":"2.0","id":0,"result":{...}}
// or any subset. MCP JSON-RPC responses are paired with their buffered POST.
func (p *parser) emitSSEFrame(key connKey, req *http.Request, frame []byte) {
	if p.emit == nil {
		return
	}
	var dataPayload []byte
	for _, raw := range bytes.Split(frame, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		if bytes.HasPrefix(line, []byte("data:")) {
			dataPayload = bytes.TrimSpace(line[len("data:"):])
			break
		}
	}
	if len(dataPayload) == 0 {
		return
	}
	var j map[string]any
	if err := json.Unmarshal(dataPayload, &j); err != nil {
		return
	}

	// MCP JSON-RPC response: pair with pending POST by id.
	if j["jsonrpc"] == "2.0" {
		if id, ok := j["id"].(float64); ok {
			if pending, ok := p.mcpPending[key.PID][id]; ok {
				p.emit(p.buildMCPPairedEvent(key, pending, j))
				delete(p.mcpPending[key.PID], id)
				return
			}
			// Unpaired (e.g., daemon started mid-session) — emit alone.
			p.emit(p.buildMCPStandaloneEvent(key, req, j))
			return
		}
	}
	// Non-RPC SSE frame (LLM streaming chunk, MCP endpoint announcement) —
	// fall through to normal stream-close summarization path. Nothing to emit
	// per-frame; the terminal buildEvent() still runs on stream close.
}

func (p *parser) buildMCPPairedEvent(key connKey, pending *pendingMCPPost, resObj map[string]any) *AgentEvent {
	// Register the peer as MCP so subsequent calls that bypass the SSE
	// pairing path (notifications, non-id requests) classify correctly.
	registerEndpoint(p.mcpEndpoints, pending.peer, maxMCPEndpoints, "MCP")
	latency := time.Since(pending.reqTime).Seconds() * 1000
	reqBodyMap := map[string]any{
		"jsonrpc": "2.0",
		"method":  pending.method,
	}
	// Rebuild a `params` map when we have meaningful data. Keeping the
	// printer's contract {"name", "arguments"} makes `tools/call add({...})`
	// render consistently; other methods can use a bare arguments blob.
	if pending.toolName != "" || pending.arguments != nil {
		params := map[string]any{}
		if pending.toolName != "" {
			params["name"] = pending.toolName
		}
		if pending.arguments != nil {
			params["arguments"] = pending.arguments
		}
		reqBodyMap["params"] = params
	}
	reqJSON, _ := json.Marshal(map[string]any{
		"method": "POST", "path": pending.req.URL.Path, "body": reqBodyMap,
	})
	resJSON, _ := json.Marshal(map[string]any{
		"status": 200, "body": resObj,
	})
	return &AgentEvent{
		Host:      key.Host, PID: key.PID,
		Timestamp: float64(time.Now().UnixMilli()) / 1000,
		Direction: "send",
		CommType:  "Agent↔MCP",
		Peer:      pending.peer,
		Request:   string(reqJSON),
		Response:  string(resJSON),
		LatencyMs: latency,
	}
}

func (p *parser) buildMCPStandaloneEvent(key connKey, req *http.Request, resObj map[string]any) *AgentEvent {
	reqJSON, _ := json.Marshal(map[string]any{
		"method": req.Method, "path": req.URL.Path, "body": nil,
	})
	resJSON, _ := json.Marshal(map[string]any{
		"status": 200, "body": resObj,
	})
	return &AgentEvent{
		Host:      key.Host, PID: key.PID,
		Timestamp: float64(time.Now().UnixMilli()) / 1000,
		Direction: "send",
		CommType:  "Agent↔MCP",
		Peer:      req.Host,
		Request:   string(reqJSON),
		Response:  string(resJSON),
		LatencyMs: 0,
	}
}

// unchunk strips HTTP/1.1 chunked-transfer framing from a body. Returns
// the original bytes if framing is malformed (best-effort).
func unchunk(b []byte) []byte {
	var out []byte
	for len(b) > 0 {
		crlf := bytes.Index(b, []byte("\r\n"))
		if crlf < 0 {
			break
		}
		sizeStr := string(b[:crlf])
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil {
			return b
		}
		b = b[crlf+2:]
		if size == 0 {
			break
		}
		if int(size) > len(b) {
			out = append(out, b...)
			break
		}
		out = append(out, b[:size]...)
		b = b[size:]
		if len(b) >= 2 && b[0] == '\r' && b[1] == '\n' {
			b = b[2:]
		}
	}
	return out
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}

func looksLikeHTTP(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if bytes.HasPrefix(b, []byte("HTTP/")) {
		return true
	}
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, []byte(m)) {
			return true
		}
	}
	return false
}

func trimToHTTPRequest(b []byte) []byte {
	best := -1
	for _, m := range httpMethods {
		if i := bytes.Index(b, []byte(m)); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	if best > 0 {
		return b[best:]
	}
	return b
}

func trimToHTTPResponse(b []byte) []byte {
	if i := bytes.Index(b, []byte("HTTP/1.")); i > 0 {
		return b[i:]
	}
	return b
}

// requestComplete mirrors responseComplete for requests. Some clients send
// headers and body in separate SSL_write calls.
func requestComplete(b []byte) bool {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}
	head := b[:headerEnd]
	bodyStart := headerEnd + 4

	lower := bytes.ToLower(head)
	if i := bytes.Index(lower, []byte("\r\ntransfer-encoding: chunked")); i >= 0 {
		return bytes.Contains(b[bodyStart:], []byte("\r\n0\r\n\r\n"))
	}
	if i := bytes.Index(lower, []byte("\r\ncontent-length:")); i >= 0 {
		rest := head[i+len("\r\ncontent-length:"):]
		if nl := bytes.Index(rest, []byte("\r\n")); nl >= 0 {
			rest = rest[:nl]
		}
		var n int
		for _, c := range bytes.TrimSpace(rest) {
			if c < '0' || c > '9' {
				return true
			}
			n = n*10 + int(c-'0')
		}
		return len(b)-bodyStart >= n
	}
	return true
}

// responseComplete reports whether b holds a complete HTTP/1 response
// (headers terminated by CRLFCRLF, plus either Content-Length bytes of body
// or a chunked terminator).
//
// For Server-Sent Events (text/event-stream), the stream is considered
// complete when a terminal marker ("data: [DONE]") appears in the body,
// so agents that stream LLM tokens can be emitted without waiting for
// TCP close or transfer-encoding chunked terminator.
func responseComplete(b []byte) bool {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}
	head := b[:headerEnd]
	bodyStart := headerEnd + 4
	lowerHead := bytes.ToLower(head)

	if bytes.Contains(lowerHead, []byte("content-type: text/event-stream")) {
		// SSE streams end either with an OpenAI-style "data: [DONE]" marker
		// or (for providers like Gemini) with just the HTTP chunked terminator.
		body := b[bodyStart:]
		if bytes.Contains(body, []byte("data: [DONE]")) {
			return true
		}
		return bytes.Contains(body, []byte("\r\n0\r\n\r\n")) ||
			bytes.Contains(body, []byte("0\r\n\r\n"))
	}

	if i := bytes.Index(lowerHead, []byte("\r\ntransfer-encoding: chunked")); i >= 0 {
		return bytes.Contains(b[bodyStart:], []byte("\r\n0\r\n\r\n")) ||
			bytes.Contains(b[bodyStart:], []byte("0\r\n\r\n"))
	}
	if i := bytes.Index(bytes.ToLower(head), []byte("\r\ncontent-length:")); i >= 0 {
		rest := head[i+len("\r\ncontent-length:"):]
		if nl := bytes.Index(rest, []byte("\r\n")); nl >= 0 {
			rest = rest[:nl]
		}
		var n int
		for _, c := range bytes.TrimSpace(rest) {
			if c < '0' || c > '9' {
				return true // malformed → accept what we have
			}
			n = n*10 + int(c-'0')
		}
		return len(b)-bodyStart >= n
	}
	// No length info → treat as complete once we have headers + some body.
	return true
}

func (p *parser) buildEvent(key connKey, req *http.Request, res *http.Response) *AgentEvent {
	latency := time.Since(p.reqTime[key]).Seconds() * 1000
	reqBody := decodeBody(readAll(req.Body), req.Header.Get("Content-Encoding"))
	resBody := decodeBody(readAll(res.Body), res.Header.Get("Content-Encoding"))

	var resBodyJSON any
	if isSSEContentType(res.Header.Get("Content-Type")) {
		resBodyJSON = decodeSSEBody(resBody)
	} else {
		resBodyJSON = tryJSON(resBody)
	}

	reqJSON, _ := json.Marshal(map[string]any{
		"method": req.Method,
		"path":   req.URL.Path,
		"body":   tryJSON(reqBody),
	})
	resJSON, _ := json.Marshal(map[string]any{
		"status": res.StatusCode,
		"body":   resBodyJSON,
	})

	return &AgentEvent{
		Host:        key.Host,
		PID:         key.PID,
		Timestamp:   float64(time.Now().UnixMilli()) / 1000,
		Direction:   "send",
		CommType:    classifyComm(req.Host, req.Method, req.URL.Path, reqBody, resBody, p.configPeers, p.llmEndpoints, p.mcpEndpoints),
		ContentType: classifyContent(reqBody),
		Peer:        req.Host,
		Request:     string(reqJSON),
		Response:    string(resJSON),
		LatencyMs:   latency,
	}
}

// classifyComm returns the comm-type label. Ordering matters:
//
//  1. configPeers — user-declared overrides (YAML + -peer flag), highest priority
//  2. llmHosts — static well-known LLM API hostnames (O(1), short-circuit)
//  3. llmEndpoints / mcpEndpoints — peers previously tagged by signature
//  4. isLLMResponse — OpenAI/Anthropic/Ollama/Gemini response shape → register + Model
//  5. isInitializeHandshake — MCP initialize round-trip → register + MCP
//  6. MCP method fallback — tools/*, resources/*, prompts/* for mid-session attach
//  7. isA2AProtocol — Google A2A tasks/* or /.well-known/agent.json
//  8. isLangGraphProtocol — /threads, /runs/{wait,stream,batch}
//  9. Unknown — everything else (health checks, metrics, unknown services)
//
// Maps are accessed under the parser mutex.
func classifyComm(peer, method, path string, reqBody, resBody []byte, cfgPeers map[string]string, llmReg, mcpReg map[string]struct{}) string {
	host := strings.Split(peer, ":")[0]

	// 1. Explicit user override — full peer first, then bare host fallback
	//    (so a user writing "api.openai.com" matches both "api.openai.com"
	//    and "api.openai.com:443" forms).
	if v, ok := cfgPeers[peer]; ok {
		return v
	}
	if host != peer {
		if v, ok := cfgPeers[host]; ok {
			return v
		}
	}

	if llmHosts[host] {
		return "Agent↔Model"
	}

	// Fast paths for already-registered endpoints.
	if _, ok := llmReg[peer]; ok {
		return "Agent↔Model"
	}
	if _, ok := mcpReg[peer]; ok {
		return "Agent↔MCP"
	}

	// LLM response fingerprint (covers Ollama / vLLM / LiteLLM self-hosted).
	if isLLMResponse(resBody) {
		registerEndpoint(llmReg, peer, maxLLMEndpoints, "LLM")
		return "Agent↔Model"
	}

	// MCP: strong signal = initialize handshake with protocolVersion.
	for _, body := range [][]byte{reqBody, resBody} {
		if isInitializeHandshake(body) {
			registerEndpoint(mcpReg, peer, maxMCPEndpoints, "MCP")
			return "Agent↔MCP"
		}
	}

	// MCP fallback: tools/*, resources/*, prompts/* method in JSON-RPC body.
	for _, body := range [][]byte{reqBody, resBody} {
		if hasMCPMethod(body) {
			registerEndpoint(mcpReg, peer, maxMCPEndpoints, "MCP")
			return "Agent↔MCP"
		}
	}

	// Agent↔Agent: only when we can identify the protocol explicitly.
	if isA2AProtocol(reqBody, method, path) {
		return "Agent↔Agent"
	}
	if isLangGraphProtocol(path) {
		return "Agent↔Agent"
	}

	return "Unknown"
}

// isLLMResponse detects the canonical response shape of the major LLM
// providers. Works on both plain JSON bodies and raw SSE bodies (looks
// inside the first `data:` event payload).
func isLLMResponse(body []byte) bool {
	if matchLLMShape(body) {
		return true
	}
	// SSE: scan a bounded number of data: lines from the front.
	if bytes.Contains(body, []byte("\ndata:")) || bytes.HasPrefix(body, []byte("data:")) {
		scanned := 0
		for _, line := range bytes.Split(body, []byte("\n")) {
			line = bytes.TrimRight(line, "\r")
			if !bytes.HasPrefix(line, []byte("data:")) {
				continue
			}
			payload := bytes.TrimSpace(line[len("data:"):])
			if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
				continue
			}
			if matchLLMShape(payload) {
				return true
			}
			scanned++
			if scanned >= 4 {
				break
			}
		}
	}
	return false
}

func matchLLMShape(body []byte) bool {
	var j map[string]any
	if json.Unmarshal(body, &j) != nil {
		return false
	}
	// OpenAI chat/text completions (incl. streaming "chat.completion.chunk")
	if obj, _ := j["object"].(string); strings.HasPrefix(obj, "chat.completion") ||
		obj == "text_completion" {
		return true
	}
	// Anthropic non-streaming messages
	if j["type"] == "message" && j["role"] == "assistant" {
		return true
	}
	// Anthropic streaming first event
	if j["type"] == "message_start" {
		if m, _ := j["message"].(map[string]any); m != nil {
			if m["type"] == "message" && m["role"] == "assistant" {
				return true
			}
		}
	}
	// Ollama native (/api/chat, /api/generate): "done" and "model" present
	_, hasDone := j["done"]
	_, hasModel := j["model"]
	if hasDone && hasModel {
		return true
	}
	// Gemini native (:generateContent, :streamGenerateContent)
	_, hasCandidates := j["candidates"]
	_, hasModelVersion := j["modelVersion"]
	if hasCandidates && hasModelVersion {
		return true
	}
	return false
}

// isInitializeHandshake returns true when body is an MCP `initialize`
// request. MCP mandates `params.protocolVersion`; no other JSON-RPC 2.0
// service uses this exact shape.
func isInitializeHandshake(body []byte) bool {
	var j map[string]any
	if json.Unmarshal(body, &j) != nil {
		return false
	}
	if j["jsonrpc"] != "2.0" {
		return false
	}
	if j["method"] != "initialize" {
		return false
	}
	params, ok := j["params"].(map[string]any)
	if !ok {
		return false
	}
	_, has := params["protocolVersion"]
	return has
}

// hasMCPMethod returns true if body is a JSON-RPC 2.0 request whose method
// is in the MCP namespace (tools/*, resources/*, prompts/*). Used as a
// fallback when the daemon joins an MCP session mid-way.
func hasMCPMethod(body []byte) bool {
	var j map[string]any
	if json.Unmarshal(body, &j) != nil || j["jsonrpc"] != "2.0" {
		return false
	}
	m, _ := j["method"].(string)
	return strings.HasPrefix(m, "tools/") ||
		strings.HasPrefix(m, "resources/") ||
		strings.HasPrefix(m, "prompts/")
}

// isA2AProtocol detects Google Agent-to-Agent protocol traffic. Covers
// both the legacy and current (a2a-sdk ≥ 0.3) method/path conventions.
func isA2AProtocol(reqBody []byte, method, path string) bool {
	// Agent Card discovery — both spellings used in the wild.
	cleanPath := path
	if i := strings.IndexByte(cleanPath, '?'); i >= 0 {
		cleanPath = cleanPath[:i]
	}
	if method == "GET" {
		if strings.HasSuffix(cleanPath, "/.well-known/agent.json") ||
			strings.HasSuffix(cleanPath, "/.well-known/agent-card.json") {
			return true
		}
	}
	// JSON-RPC 2.0 A2A methods — current SDK uses `message/send`,
	// `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/pushNotificationConfig/*`,
	// `tasks/resubscribe`. Legacy spec used `tasks/send`.
	var j map[string]any
	if json.Unmarshal(reqBody, &j) == nil && j["jsonrpc"] == "2.0" {
		m, _ := j["method"].(string)
		if strings.HasPrefix(m, "tasks/") ||
			strings.HasPrefix(m, "message/") ||
			m == "agent/getAuthenticatedExtendedCard" {
			return true
		}
	}
	return false
}

// isLangGraphProtocol detects LangGraph Agent Protocol REST endpoints.
// Matches only the specific paths from the spec (POST /threads, runs
// subpaths) to avoid false positives from generic `/runs` or `/threads`
// endpoints in unrelated services.
func isLangGraphProtocol(path string) bool {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "/threads" || strings.HasPrefix(path, "/threads/") {
		return true
	}
	switch path {
	case "/runs", "/runs/wait", "/runs/stream", "/runs/batch":
		return true
	}
	return false
}

// registerEndpoint adds peer to reg, capped at max. Emits a log line the
// first time a peer is registered so operators see classifier state grow.
func registerEndpoint(reg map[string]struct{}, peer string, max int, label string) {
	if peer == "" {
		return
	}
	if _, ok := reg[peer]; ok {
		return
	}
	if len(reg) >= max {
		return
	}
	reg[peer] = struct{}{}
	log.Printf("parser: %s endpoint registered: %s (total=%d)", label, peer, len(reg))
}

func classifyContent(body []byte) string {
	var j map[string]any
	if json.Unmarshal(body, &j) != nil {
		return "TEXT"
	}
	msgs, _ := j["messages"].([]any)
	for i := len(msgs) - 1; i >= 0; i-- {
		msg, _ := msgs[i].(map[string]any)
		if msg == nil {
			continue
		}
		switch v := msg["content"].(type) {
		case []any:
			for _, b := range v {
				block, _ := b.(map[string]any)
				switch block["type"] {
				case "image_url", "image":
					return "IMAGE"
				case "document":
					return "FILE"
				}
			}
		case string:
			if msg["role"] == "tool" && len(v) > 2000 {
				return "FILE_READ"
			}
		}
	}
	return "TEXT"
}

func decodeBody(b []byte, encoding string) []byte {
	if len(b) == 0 {
		return b
	}
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip":
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return b
		}
		return out
	case "deflate":
		r, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return b
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			return b
		}
		return out
	}
	return b
}

func readAll(r io.ReadCloser) []byte {
	if r == nil {
		return nil
	}
	b, _ := io.ReadAll(r)
	r.Close()
	return b
}

func tryJSON(b []byte) any {
	var v any
	if json.Unmarshal(b, &v) == nil {
		return v
	}
	return string(b)
}

// decodeSSEBody parses a Server-Sent Events body and merges the deltas into
// a single response. Text fragments from provider-specific delta formats
// (OpenAI `choices[].delta.content`, Anthropic `delta.text`, Gemini
// `candidates[].content.parts[].text`, plus simple `delta` / `text` /
// `content` strings) are concatenated. The terminal `[DONE]` sentinel
// and non-`data:` framing lines are ignored. Useful metadata from the
// final event (finishReason, usageMetadata, modelVersion, responseId) is
// preserved so callers can still see why generation stopped and how many
// tokens were consumed. If no text can be extracted the raw event list
// is returned instead.
func decodeSSEBody(b []byte) any {
	if len(b) == 0 {
		return ""
	}
	events := []any{}
	for _, raw := range bytes.Split(b, []byte("\n")) {
		line := bytes.TrimRight(raw, "\r")
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
			continue
		}
		var v any
		if err := json.Unmarshal(payload, &v); err == nil {
			events = append(events, v)
		} else {
			events = append(events, string(payload))
		}
	}
	if len(events) == 0 {
		return string(b)
	}
	return mergeSSEEvents(events)
}

func mergeSSEEvents(events []any) any {
	var buf strings.Builder
	var lastObj map[string]any
	for _, e := range events {
		obj, ok := e.(map[string]any)
		if !ok {
			continue
		}
		lastObj = obj
		buf.WriteString(extractSSEText(obj))
	}
	if buf.Len() == 0 {
		// No text extracted — keep the event list verbatim so debugging info isn't lost.
		return events
	}
	out := map[string]any{
		"text":   buf.String(),
		"chunks": len(events),
	}
	if lastObj != nil {
		for _, k := range []string{"finishReason", "modelVersion", "responseId", "usageMetadata", "model", "id"} {
			if v, ok := lastObj[k]; ok {
				out[k] = v
			}
		}
		// Gemini nests finishReason inside candidates[0].
		if _, has := out["finishReason"]; !has {
			if cands, ok := lastObj["candidates"].([]any); ok && len(cands) > 0 {
				if c0, ok := cands[0].(map[string]any); ok {
					if fr, ok := c0["finishReason"]; ok {
						out["finishReason"] = fr
					}
				}
			}
		}
	}
	return out
}

func extractSSEText(ev map[string]any) string {
	// Gemini: candidates[*].content.parts[*].text
	if cands, ok := ev["candidates"].([]any); ok {
		var b strings.Builder
		for _, c := range cands {
			co, _ := c.(map[string]any)
			if co == nil {
				continue
			}
			content, _ := co["content"].(map[string]any)
			if content == nil {
				continue
			}
			parts, _ := content["parts"].([]any)
			for _, p := range parts {
				po, _ := p.(map[string]any)
				if po == nil {
					continue
				}
				if t, ok := po["text"].(string); ok {
					b.WriteString(t)
				}
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	// OpenAI: choices[*].delta.content
	if choices, ok := ev["choices"].([]any); ok {
		var b strings.Builder
		for _, c := range choices {
			co, _ := c.(map[string]any)
			if co == nil {
				continue
			}
			delta, _ := co["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			if t, ok := delta["content"].(string); ok {
				b.WriteString(t)
			}
		}
		if b.Len() > 0 {
			return b.String()
		}
	}
	// Anthropic: delta.text (content_block_delta events)
	if delta, ok := ev["delta"].(map[string]any); ok {
		if t, ok := delta["text"].(string); ok {
			return t
		}
	}
	// Generic fallbacks
	if s, ok := ev["delta"].(string); ok {
		return s
	}
	if s, ok := ev["text"].(string); ok {
		return s
	}
	if s, ok := ev["content"].(string); ok {
		return s
	}
	return ""
}

// isSSEContentType reports whether the given Content-Type header value
// represents a Server-Sent Events stream.
func isSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}
