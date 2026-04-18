package master

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	blue   = "\033[34m"
	yellow = "\033[33m"
	green  = "\033[32m"
	gray   = "\033[90m"
	cyan   = "\033[36m"
)

type Event struct {
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

type printer struct{ verbose bool }

func newPrinter(verbose bool) *printer { return &printer{verbose} }

func (p *printer) print(e *Event) {
	ts := time.Unix(0, int64(e.Timestamp*1e9)).Format("15:04:05")
	tag, ok := map[string]string{
		"Agent↔Model": blue + "Agent↔Model" + reset,
		"Agent↔Agent": yellow + "Agent↔Agent" + reset,
		"Agent↔MCP":   green + "Agent↔MCP  " + reset,
		"Unknown":     gray + "Unknown    " + reset,
	}[e.CommType]
	if !ok {
		tag = gray + "Unknown    " + reset
	}

	var req map[string]any
	_ = json.Unmarshal([]byte(e.Request), &req)
	var res map[string]any
	_ = json.Unmarshal([]byte(e.Response), &res)

	method, _ := req["method"].(string)
	path, _ := req["path"].(string)
	status := 0
	if v, ok := res["status"].(float64); ok {
		status = int(v)
	}
	statusStr := colorStatus(status)

	// Header: one compact line with the key routing info
	fmt.Printf("%s[%s]%s %s  %-6s %s  %s  %5.0fms  %s\n",
		gray, ts, reset,
		tag,
		method, truncate(path, 60),
		statusStr,
		e.LatencyMs,
		gray+fmt.Sprintf("%s • PID %d • %s", e.Peer, e.PID, e.Host)+reset,
	)

	reqBody := req["body"]
	resBody := res["body"]

	if p.verbose {
		fmt.Printf("  %sreq%s  %s\n", gray, reset, prettyIndent(reqBody))
		fmt.Printf("  %sres%s  %s\n", gray, reset, prettyIndent(resBody))
	} else {
		fmt.Printf("  %sreq%s  %s\n", gray, reset, summarizeBody(reqBody, 140))
		fmt.Printf("  %sres%s  %s\n", gray, reset, summarizeBody(resBody, 140))
	}
	fmt.Println(strings.Repeat("─", 90))
}

func colorStatus(s int) string {
	if s == 0 {
		return gray + "---" + reset
	}
	str := fmt.Sprintf("%d", s)
	switch {
	case s >= 500:
		return red + bold + str + reset
	case s >= 400:
		return red + str + reset
	case s >= 300:
		return yellow + str + reset
	case s >= 200:
		return green + str + reset
	}
	return str
}

// summarizeBody produces a short, human-oriented preview. For SSE merged
// results it surfaces the extracted text; for objects it shows a compact
// inline JSON; for strings it truncates directly.
func summarizeBody(body any, maxLen int) string {
	if body == nil {
		return gray + "(empty)" + reset
	}
	switch v := body.(type) {
	case string:
		if v == "" {
			return gray + "(empty)" + reset
		}
		return fmt.Sprintf("%q", truncate(v, maxLen))
	case map[string]any:
		// SSE merged shape: {"text": "...", "chunks": N, "finishReason": "..."}
		if text, ok := v["text"].(string); ok {
			suffix := ""
			if chunks, ok := v["chunks"].(float64); ok {
				reason, _ := v["finishReason"].(string)
				if reason != "" {
					suffix = fmt.Sprintf("  %s(%d chunks, %s)%s", gray, int(chunks), reason, reset)
				} else {
					suffix = fmt.Sprintf("  %s(%d chunks)%s", gray, int(chunks), reset)
				}
			}
			return fmt.Sprintf("%q%s", truncate(text, maxLen), suffix)
		}
	}
	// Fallback: marshal and truncate
	raw, err := json.Marshal(body)
	if err != nil {
		return truncate(fmt.Sprintf("%v", body), maxLen)
	}
	return truncate(string(raw), maxLen)
}

func prettyIndent(v any) string {
	b, err := json.MarshalIndent(v, "      ", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return "\n      " + string(b)
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
