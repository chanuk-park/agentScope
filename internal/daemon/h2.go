package daemon

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"
)

const (
	h2Preface      = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	frameHeaderLen = 9

	frameDATA         = 0x0
	frameHEADERS      = 0x1
	framePRIORITY     = 0x2
	frameSETTINGS     = 0x4
	framePING         = 0x6
	frameGOAWAY       = 0x7
	frameWINDOW       = 0x8
	frameCONTINUATION = 0x9

	h2FlagEndStream  = 0x1
	h2FlagEndHeaders = 0x4
	h2FlagPadded     = 0x8
	h2FlagPriority   = 0x20
)

type h2Stream struct {
	reqHeaders http.Header
	reqBody    bytes.Buffer
	resHeaders http.Header
	resBody    bytes.Buffer
	reqEnded   bool
	resEnded   bool
	reqTime    time.Time

	pendingBlock    bytes.Buffer // accumulates HEADERS + CONTINUATION
	pendingIsReq    bool
	pendingEndStrm  bool
	pendingActive   bool
}

type h2Conn struct {
	sendBuf         []byte
	recvBuf         []byte
	sendDec         *hpack.Decoder
	recvDec         *hpack.Decoder
	streams         map[uint32]*h2Stream
	prefaceConsumed bool
}

func newH2Conn() *h2Conn {
	return &h2Conn{
		sendDec: hpack.NewDecoder(4096, nil),
		recvDec: hpack.NewDecoder(4096, nil),
		streams: make(map[uint32]*h2Stream),
	}
}

func looksLikeH2Preface(b []byte) bool {
	return bytes.HasPrefix(b, []byte(h2Preface))
}

func (c *h2Conn) stream(id uint32) *h2Stream {
	s := c.streams[id]
	if s == nil {
		s = &h2Stream{reqHeaders: http.Header{}, resHeaders: http.Header{}}
		c.streams[id] = s
	}
	return s
}

// feed consumes SSL event bytes and returns a completed AgentEvent when a
// stream has observed END_STREAM in both directions.
func (c *h2Conn) feed(sendDir bool, data []byte, peer, hostname string, pid uint32) *AgentEvent {
	var buf *[]byte
	if sendDir {
		buf = &c.sendBuf
	} else {
		buf = &c.recvBuf
	}
	*buf = append(*buf, data...)

	if sendDir && !c.prefaceConsumed {
		if len(*buf) < len(h2Preface) {
			return nil
		}
		if !bytes.HasPrefix(*buf, []byte(h2Preface)) {
			return nil
		}
		*buf = (*buf)[len(h2Preface):]
		c.prefaceConsumed = true
	}

	for {
		if len(*buf) < frameHeaderLen {
			break
		}
		length := uint32((*buf)[0])<<16 | uint32((*buf)[1])<<8 | uint32((*buf)[2])
		if int(length)+frameHeaderLen > len(*buf) {
			break
		}
		ftype := (*buf)[3]
		flags := (*buf)[4]
		streamID := binary.BigEndian.Uint32((*buf)[5:9]) & 0x7fffffff
		payload := make([]byte, length)
		copy(payload, (*buf)[frameHeaderLen:frameHeaderLen+int(length)])
		*buf = (*buf)[frameHeaderLen+int(length):]

		if evt := c.handleFrame(sendDir, ftype, flags, streamID, payload, peer, hostname, pid); evt != nil {
			return evt
		}
	}
	return nil
}

func (c *h2Conn) handleFrame(sendDir bool, ftype, flags byte, streamID uint32, payload []byte, peer, hostname string, pid uint32) *AgentEvent {
	switch ftype {
	case frameSETTINGS, framePING, frameGOAWAY, frameWINDOW, framePRIORITY, 0x3 /*RST*/, 0x5 /*PUSH_PROMISE*/ :
		return nil
	case frameHEADERS:
		if streamID == 0 {
			return nil
		}
		hb := trimHeadersPayload(flags, payload)
		s := c.stream(streamID)
		s.pendingBlock.Reset()
		s.pendingBlock.Write(hb)
		s.pendingIsReq = sendDir
		s.pendingEndStrm = flags&h2FlagEndStream != 0
		s.pendingActive = true
		if flags&h2FlagEndHeaders != 0 {
			return c.commitHeaders(s, streamID, peer, hostname, pid)
		}
	case frameCONTINUATION:
		s := c.streams[streamID]
		if s == nil || !s.pendingActive {
			return nil
		}
		s.pendingBlock.Write(payload)
		if flags&h2FlagEndHeaders != 0 {
			return c.commitHeaders(s, streamID, peer, hostname, pid)
		}
	case frameDATA:
		if streamID == 0 {
			return nil
		}
		s := c.stream(streamID)
		data := payload
		if flags&h2FlagPadded != 0 && len(data) > 0 {
			pl := int(data[0])
			if pl+1 > len(data) {
				return nil
			}
			data = data[1 : len(data)-pl]
		}
		if sendDir {
			s.reqBody.Write(data)
			if flags&h2FlagEndStream != 0 {
				s.reqEnded = true
				s.reqTime = time.Now()
			}
		} else {
			s.resBody.Write(data)
			if flags&h2FlagEndStream != 0 {
				s.resEnded = true
			}
		}
		return c.maybeEmit(s, streamID, peer, hostname, pid)
	}
	return nil
}

func trimHeadersPayload(flags byte, p []byte) []byte {
	if flags&h2FlagPadded != 0 && len(p) > 0 {
		pl := int(p[0])
		if pl+1 > len(p) {
			return nil
		}
		p = p[1 : len(p)-pl]
	}
	if flags&h2FlagPriority != 0 {
		if len(p) < 5 {
			return nil
		}
		p = p[5:]
	}
	return p
}

func (c *h2Conn) commitHeaders(s *h2Stream, streamID uint32, peer, hostname string, pid uint32) *AgentEvent {
	dec := c.sendDec
	target := s.reqHeaders
	if !s.pendingIsReq {
		dec = c.recvDec
		target = s.resHeaders
	}
	hdrs, err := dec.DecodeFull(s.pendingBlock.Bytes())
	if err != nil {
		s.pendingActive = false
		s.pendingBlock.Reset()
		return nil
	}
	for _, h := range hdrs {
		target.Add(h.Name, h.Value)
	}
	if s.pendingEndStrm {
		if s.pendingIsReq {
			s.reqEnded = true
			s.reqTime = time.Now()
		} else {
			s.resEnded = true
		}
	}
	s.pendingActive = false
	s.pendingBlock.Reset()
	return c.maybeEmit(s, streamID, peer, hostname, pid)
}

func (c *h2Conn) maybeEmit(s *h2Stream, streamID uint32, peer, hostname string, pid uint32) *AgentEvent {
	if !s.reqEnded {
		return nil
	}
	if !s.resEnded {
		// Server-Sent Events: emit as soon as the terminal "[DONE]" marker
		// appears in the response body. The server normally closes the stream
		// right after, but we don't wait — streaming LLM responses can be
		// shown to the user immediately.
		if !isSSEResponse(s.resHeaders) ||
			!bytes.Contains(s.resBody.Bytes(), []byte("data: [DONE]")) {
			return nil
		}
	}
	method := s.reqHeaders.Get(":method")
	path := s.reqHeaders.Get(":path")
	authority := s.reqHeaders.Get(":authority")
	status := s.resHeaders.Get(":status")
	if authority == "" {
		authority = peer
	}

	reqBody := s.reqBody.Bytes()
	resBody := s.resBody.Bytes()

	reqJSON, _ := json.Marshal(map[string]any{
		"method": method,
		"path":   path,
		"body":   tryJSON(reqBody),
	})
	statusCode := 0
	if status != "" {
		statusCode = atoiSafe(status)
	}
	resJSON, _ := json.Marshal(map[string]any{
		"status": statusCode,
		"body":   tryJSON(resBody),
	})

	latency := float64(0)
	if !s.reqTime.IsZero() {
		latency = time.Since(s.reqTime).Seconds() * 1000
	}

	evt := &AgentEvent{
		Host:        hostname,
		PID:         pid,
		Timestamp:   float64(time.Now().UnixMilli()) / 1000,
		Direction:   "send",
		CommType:    classifyComm(authority, reqBody, resBody),
		ContentType: classifyContent(reqBody),
		Peer:        authority,
		Request:     string(reqJSON),
		Response:    string(resJSON),
		LatencyMs:   latency,
	}
	delete(c.streams, streamID)
	return evt
}

func isSSEResponse(h http.Header) bool {
	return strings.Contains(strings.ToLower(h.Get("content-type")), "text/event-stream")
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}
