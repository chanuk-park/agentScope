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

// connKey: Source separates TLS and PLAIN pointer spaces so they can't collide.
type connKey struct {
	Host   string
	PID    uint32
	Conn   uint64
	Source uint8
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
	proto    map[connKey]byte // 0=unknown, 1=http/1, 2=http/2
	hostname string

	// SSE streams stay open for minutes; track per-key offset so we emit each new frame once.
	sseEmittedBytes map[connKey]int

	// MCP POST /messages/ → SSE pairing keyed by PID + jsonrpc id (request and response on different conns).
	mcpPending map[uint32]map[float64]*pendingMCPPost

	// emit forwards side-channel events (per-frame MCP pairs) outside the feed() return path.
	emit func(*AgentEvent)

	// Endpoints registered after first signature match, then O(1) on subsequent calls. Outlive any single PID.
	llmEndpoints map[string]struct{}
	mcpEndpoints map[string]struct{}

	// configPeers: user-declared comm-type overrides, consulted before any heuristic.
	configPeers map[string]string
}

type pendingMCPPost struct {
	req       *http.Request
	method    string
	toolName  string
	arguments any
	peer      string
	reqTime   time.Time
}

const (
	maxLLMEndpoints = 1024
	maxMCPEndpoints = 1024
)

// evictPID drops every connKey buffer tied to pid. Called when an agent process exits.
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
		writeBuf:        make(map[connKey][]byte),
		readBuf:         make(map[connKey][]byte),
		reqTime:         make(map[connKey]time.Time),
		lastReq:         make(map[connKey]*http.Request),
		sseEmittedBytes: make(map[connKey]int),
		mcpPending:      make(map[uint32]map[float64]*pendingMCPPost),
		h2:              make(map[connKey]*h2Conn),
		proto:           make(map[connKey]byte),
		hostname:        hostname,
		llmEndpoints:    make(map[string]struct{}),
		mcpEndpoints:    make(map[string]struct{}),
		configPeers:     configPeers,
	}
}

func (p *parser) feed(raw RawEvent) *AgentEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := connKey{Host: p.hostname, PID: raw.PID, Conn: raw.Conn, Source: raw.Source}

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

	// Drop TLS handshake artifacts and zero-filled session-ticket reads.
	if !looksLikeHTTP(raw.Data) && len(p.writeBuf[key]) == 0 && len(p.readBuf[key]) == 0 {
		return nil
	}

	switch raw.Dir {
	case 0: // DIR_WRITE
		p.writeBuf[key] = append(p.writeBuf[key], raw.Data...)
		p.writeBuf[key] = trimToHTTPRequest(p.writeBuf[key])
		if !requestComplete(p.writeBuf[key]) {
			return nil
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p.writeBuf[key])))
		if err != nil {
			return nil
		}

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
		p.readBuf[key] = nil

	case 1: // DIR_READ
		req := p.lastReq[key]
		if req == nil {
			return nil
		}
		p.readBuf[key] = append(p.readBuf[key], raw.Data...)
		p.readBuf[key] = trimToHTTPResponse(p.readBuf[key])

		// MCP streams emit per-frame here; LLM streams fall through to buildEvent at "data: [DONE]".
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

// tryBufferMCPPost stashes MCP JSON-RPC POST /messages/ requests by jsonrpc id for SSE pairing later.
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
	if !hasID {
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

// maybeEmitSSEFrames emits one AgentEvent per complete `data:` frame for MCP-paired streams.
func (p *parser) maybeEmitSSEFrames(key connKey, req *http.Request) bool {
	headerEnd := bytes.Index(p.readBuf[key], []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}
	head := bytes.ToLower(p.readBuf[key][:headerEnd])
	if !bytes.Contains(head, []byte("content-type: text/event-stream")) {
		return false
	}

	bodyStart := headerEnd + 4
	body := p.readBuf[key][bodyStart:]
	if bytes.Contains(head, []byte("\r\ntransfer-encoding: chunked")) {
		body = unchunk(body)
	}

	body = bytes.ReplaceAll(body, []byte("\r\n"), []byte("\n"))

	already := p.sseEmittedBytes[key]
	if already > len(body) {
		already = 0
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

	if j["jsonrpc"] == "2.0" {
		if id, ok := j["id"].(float64); ok {
			if pending, ok := p.mcpPending[key.PID][id]; ok {
				p.emit(p.buildMCPPairedEvent(key, pending, j))
				delete(p.mcpPending[key.PID], id)
				return
			}
			p.emit(p.buildMCPStandaloneEvent(key, req, j))
			return
		}
	}
}

func (p *parser) buildMCPPairedEvent(key connKey, pending *pendingMCPPost, resObj map[string]any) *AgentEvent {
	registerEndpoint(p.mcpEndpoints, pending.peer, maxMCPEndpoints, "MCP")
	latency := time.Since(pending.reqTime).Seconds() * 1000
	reqBodyMap := map[string]any{
		"jsonrpc": "2.0",
		"method":  pending.method,
	}
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

// responseComplete: SSE streams end on "data: [DONE]" or chunked terminator.
func responseComplete(b []byte) bool {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return false
	}
	head := b[:headerEnd]
	bodyStart := headerEnd + 4
	lowerHead := bytes.ToLower(head)

	if bytes.Contains(lowerHead, []byte("content-type: text/event-stream")) {
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
				return true
			}
			n = n*10 + int(c-'0')
		}
		return len(b)-bodyStart >= n
	}
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

// classifyComm priority: configPeers → llmHosts → registered endpoints → response shape → MCP → A2A → LangGraph → Unknown.
func classifyComm(peer, method, path string, reqBody, resBody []byte, cfgPeers map[string]string, llmReg, mcpReg map[string]struct{}) string {
	host := strings.Split(peer, ":")[0]

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

	if _, ok := llmReg[peer]; ok {
		return "Agent↔Model"
	}
	if _, ok := mcpReg[peer]; ok {
		return "Agent↔MCP"
	}

	if isLLMResponse(resBody) {
		registerEndpoint(llmReg, peer, maxLLMEndpoints, "LLM")
		return "Agent↔Model"
	}

	for _, body := range [][]byte{reqBody, resBody} {
		if isInitializeHandshake(body) {
			registerEndpoint(mcpReg, peer, maxMCPEndpoints, "MCP")
			return "Agent↔MCP"
		}
	}

	for _, body := range [][]byte{reqBody, resBody} {
		if hasMCPMethod(body) {
			registerEndpoint(mcpReg, peer, maxMCPEndpoints, "MCP")
			return "Agent↔MCP"
		}
	}

	if isA2AProtocol(reqBody, method, path) {
		return "Agent↔Agent"
	}
	if isLangGraphProtocol(path) {
		return "Agent↔Agent"
	}

	return "Unknown"
}

// isLLMResponse matches OpenAI/Anthropic/Ollama/Gemini response shape on plain JSON or SSE body.
func isLLMResponse(body []byte) bool {
	if matchLLMShape(body) {
		return true
	}
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
	if obj, _ := j["object"].(string); strings.HasPrefix(obj, "chat.completion") || obj == "text_completion" {
		return true
	}
	if j["type"] == "message" && j["role"] == "assistant" {
		return true
	}
	if j["type"] == "message_start" {
		if m, _ := j["message"].(map[string]any); m != nil {
			if m["type"] == "message" && m["role"] == "assistant" {
				return true
			}
		}
	}
	_, hasDone := j["done"]
	_, hasModel := j["model"]
	if hasDone && hasModel {
		return true
	}
	_, hasCandidates := j["candidates"]
	_, hasModelVersion := j["modelVersion"]
	if hasCandidates && hasModelVersion {
		return true
	}
	return false
}

// isInitializeHandshake: MCP `initialize` with `params.protocolVersion` is unique to MCP.
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

// hasMCPMethod: tools/* / resources/* / prompts/* JSON-RPC method (mid-session attach fallback).
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

func isA2AProtocol(reqBody []byte, method, path string) bool {
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

// decodeSSEBody merges per-provider delta fragments into a single text + preserves trailing metadata.
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
		// Gemini nests finishReason under candidates[0].
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
	// Anthropic: delta.text
	if delta, ok := ev["delta"].(map[string]any); ok {
		if t, ok := delta["text"].(string); ok {
			return t
		}
	}
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

func isSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}
