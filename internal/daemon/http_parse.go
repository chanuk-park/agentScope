package daemon

import (
	"bytes"
	"errors"
	"strconv"
)

var errHTTPIncomplete = errors.New("incomplete")
var errHTTPMalformed = errors.New("malformed")

// httpReq / httpRes hold only the fields the classifier and event builder need.
// No Header map, no URL parse, no body wrapper — saves ~20 allocs per request
// compared to http.ReadRequest/ReadResponse.
type httpReq struct {
	Method          string
	Path            string // path-with-query (matches http.Request.URL.RequestURI behavior for our use)
	Host            string
	ContentEncoding string
	ContentType     string
	Body            []byte
}

type httpRes struct {
	StatusCode      int
	ContentEncoding string
	ContentType     string
	Body            []byte
}

// parseHTTPReq parses an HTTP/1.x request from a complete in-memory buffer
// (caller already verified completeness via requestComplete).
func parseHTTPReq(b []byte) (*httpReq, error) {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, errHTTPIncomplete
	}
	head := b[:headerEnd]
	bodyStart := headerEnd + 4

	nl := bytes.IndexByte(head, '\n')
	if nl < 0 {
		return nil, errHTTPMalformed
	}
	first := bytes.TrimRight(head[:nl], "\r")
	// "METHOD SP REQUEST-URI SP HTTP/x.y"
	sp1 := bytes.IndexByte(first, ' ')
	if sp1 <= 0 {
		return nil, errHTTPMalformed
	}
	sp2 := bytes.IndexByte(first[sp1+1:], ' ')
	if sp2 < 0 {
		return nil, errHTTPMalformed
	}
	r := &httpReq{
		Method: string(first[:sp1]),
		Path:   string(first[sp1+1 : sp1+1+sp2]),
	}
	// Strip query string from Path so it matches http.Request.URL.Path semantics
	// used by isLangGraphProtocol / isA2AProtocol.
	if q := bytes.IndexByte([]byte(r.Path), '?'); q >= 0 {
		r.Path = r.Path[:q]
	}

	cl, chunked := parseHeaders(head[nl+1:], func(name, val []byte) {
		switch {
		case asciiEqualFold(name, hHost):
			r.Host = string(val)
		case asciiEqualFold(name, hContentType):
			r.ContentType = string(val)
		case asciiEqualFold(name, hContentEncoding):
			r.ContentEncoding = string(val)
		}
	})

	r.Body = sliceBody(b[bodyStart:], cl, chunked)
	return r, nil
}

// parseHTTPRes parses an HTTP/1.x response.
func parseHTTPRes(b []byte) (*httpRes, error) {
	headerEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil, errHTTPIncomplete
	}
	head := b[:headerEnd]
	bodyStart := headerEnd + 4

	nl := bytes.IndexByte(head, '\n')
	if nl < 0 {
		return nil, errHTTPMalformed
	}
	first := bytes.TrimRight(head[:nl], "\r")
	// "HTTP/x.y SP STATUS SP REASON-PHRASE"
	sp1 := bytes.IndexByte(first, ' ')
	if sp1 <= 0 {
		return nil, errHTTPMalformed
	}
	rest := first[sp1+1:]
	sp2 := bytes.IndexByte(rest, ' ')
	statusBytes := rest
	if sp2 > 0 {
		statusBytes = rest[:sp2]
	}
	status, err := strconv.Atoi(string(statusBytes))
	if err != nil {
		return nil, errHTTPMalformed
	}
	r := &httpRes{StatusCode: status}

	cl, chunked := parseHeaders(head[nl+1:], func(name, val []byte) {
		switch {
		case asciiEqualFold(name, hContentType):
			r.ContentType = string(val)
		case asciiEqualFold(name, hContentEncoding):
			r.ContentEncoding = string(val)
		}
	})

	r.Body = sliceBody(b[bodyStart:], cl, chunked)
	return r, nil
}

// parseHeaders walks "Name: Value\r\n" lines, calling onHeader for each, and
// returns Content-Length (-1 if absent/invalid) + chunked flag.
func parseHeaders(headerBytes []byte, onHeader func(name, val []byte)) (contentLength int, chunked bool) {
	contentLength = -1
	for len(headerBytes) > 0 {
		nl := bytes.IndexByte(headerBytes, '\n')
		var line []byte
		if nl < 0 {
			line = headerBytes
			headerBytes = nil
		} else {
			line = headerBytes[:nl]
			headerBytes = headerBytes[nl+1:]
		}
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := line[:colon]
		val := bytes.TrimSpace(line[colon+1:])
		switch {
		case asciiEqualFold(name, hContentLength):
			if n, err := strconv.Atoi(string(val)); err == nil {
				contentLength = n
			}
		case asciiEqualFold(name, hTransferEncoding):
			// Anything containing "chunked" is treated as chunked.
			if bytes.Contains(asciiLower(val), []byte("chunked")) {
				chunked = true
			}
		default:
			onHeader(name, val)
		}
	}
	return
}

// sliceBody returns the body bytes given Content-Length / chunked.
func sliceBody(rest []byte, cl int, chunked bool) []byte {
	if chunked {
		return unchunk(rest)
	}
	if cl >= 0 {
		if cl > len(rest) {
			cl = len(rest)
		}
		return rest[:cl]
	}
	return rest
}

// asciiEqualFold compares two ASCII byte slices case-insensitively. Used for
// header-name matching — HTTP header names are ASCII per spec, so we don't need
// Unicode case folding.
func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 32
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 32
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

var (
	hHost             = []byte("Host")
	hContentType      = []byte("Content-Type")
	hContentEncoding  = []byte("Content-Encoding")
	hContentLength    = []byte("Content-Length")
	hTransferEncoding = []byte("Transfer-Encoding")
)
