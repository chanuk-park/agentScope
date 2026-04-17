package daemon

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
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
	Host string
	PID  uint32
}

var llmHosts = map[string]bool{
	"api.openai.com":                    true,
	"api.anthropic.com":                 true,
	"generativelanguage.googleapis.com": true,
	"api.groq.com":                      true,
	"api.mistral.ai":                    true,
}

type parser struct {
	writeBuf map[connKey][]byte
	readBuf  map[connKey][]byte
	reqTime  map[connKey]time.Time
	lastReq  map[connKey]*http.Request
	h2       map[connKey]*h2Conn
	proto    map[connKey]byte // 0 = unknown, 1 = http/1, 2 = http/2
	hostname string
}

func newParser(hostOverride string) *parser {
	h := hostOverride
	if h == "" {
		h, _ = os.Hostname()
	}
	return &parser{
		writeBuf: make(map[connKey][]byte),
		readBuf:  make(map[connKey][]byte),
		reqTime:  make(map[connKey]time.Time),
		lastReq:  make(map[connKey]*http.Request),
		h2:       make(map[connKey]*h2Conn),
		proto:    make(map[connKey]byte),
		hostname: h,
	}
}

func (p *parser) feed(raw RawEvent) *AgentEvent {
	key := connKey{Host: p.hostname, PID: raw.PID}

	// Protocol detection on first meaningful write. HTTP/2 connection always
	// starts with the 24-byte preface.
	if p.proto[key] == 0 && raw.Type == 0 {
		if looksLikeH2Preface(raw.Data) {
			p.proto[key] = 2
			p.h2[key] = newH2Conn()
		} else if looksLikeHTTP(raw.Data) {
			p.proto[key] = 1
		}
	}

	if p.proto[key] == 2 {
		c := p.h2[key]
		if c == nil {
			return nil
		}
		return c.feed(raw.Type == 0, raw.Data, "", p.hostname, raw.PID)
	}

	// Skip events whose payload is clearly not HTTP plaintext (TLS handshake
	// artifacts, zero-filled reads after TLS session tickets, etc.).
	if !looksLikeHTTP(raw.Data) && len(p.writeBuf[key]) == 0 && len(p.readBuf[key]) == 0 {
		return nil
	}

	switch raw.Type {
	case 0: // SSL_WRITE → send
		p.writeBuf[key] = append(p.writeBuf[key], raw.Data...)
		p.writeBuf[key] = trimToHTTPRequest(p.writeBuf[key])
		if !requestComplete(p.writeBuf[key]) {
			return nil
		}
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(p.writeBuf[key])))
		if err != nil {
			return nil
		}
		p.lastReq[key] = req
		p.reqTime[key] = time.Now()
		p.writeBuf[key] = nil
		p.readBuf[key] = nil // 새 요청 시작 시 이전 read 버퍼 초기화

	case 1: // SSL_READ → recv 완성
		req := p.lastReq[key]
		if req == nil {
			return nil // TLS 핸드셰이크 등 요청 전 read는 무시
		}
		p.readBuf[key] = append(p.readBuf[key], raw.Data...)
		p.readBuf[key] = trimToHTTPResponse(p.readBuf[key])
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
		return event
	}
	return nil
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

	reqJSON, _ := json.Marshal(map[string]any{
		"method": req.Method,
		"path":   req.URL.Path,
		"body":   tryJSON(reqBody),
	})
	resJSON, _ := json.Marshal(map[string]any{
		"status": res.StatusCode,
		"body":   tryJSON(resBody),
	})

	return &AgentEvent{
		Host:        key.Host,
		PID:         key.PID,
		Timestamp:   float64(time.Now().UnixMilli()) / 1000,
		Direction:   "send",
		CommType:    classifyComm(req.Host, reqBody, resBody),
		ContentType: classifyContent(reqBody),
		Peer:        req.Host,
		Request:     string(reqJSON),
		Response:    string(resJSON),
		LatencyMs:   latency,
	}
}

func classifyComm(peer string, reqBody, resBody []byte) string {
	host := strings.Split(peer, ":")[0]
	if llmHosts[host] {
		return "Agent↔Model"
	}
	for _, body := range [][]byte{reqBody, resBody} {
		var j map[string]any
		if json.Unmarshal(body, &j) != nil || j["jsonrpc"] != "2.0" {
			continue
		}
		if m, _ := j["method"].(string); strings.HasPrefix(m, "tools/") ||
			strings.HasPrefix(m, "resources/") ||
			strings.HasPrefix(m, "prompts/") ||
			m == "initialize" {
			return "Agent↔MCP"
		}
		// Response side: method may not exist, but "result"/"error" with jsonrpc
		// indicates JSON-RPC protocol. Peer host decides whether it is MCP —
		// MCP typically doesn't live on llmHosts, so treat jsonrpc 2.0 as MCP.
		if _, ok := j["result"]; ok {
			return "Agent↔MCP"
		}
	}
	return "Agent↔Agent"
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
