package master

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"strings"
	"sync"
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

// hostPalette holds ANSI-256 foreground codes with high contrast against a
// dark terminal, skipping colors already used for status (red/green/yellow)
// and dim text (gray). Each daemon host gets a deterministic entry via FNV
// hashing so the same host always renders in the same color.
var hostPalette = []int{39, 220, 208, 141, 51, 210, 118, 165, 45, 180}

func hostColor(host string) string {
	if host == "" {
		return gray
	}
	h := fnv.New32a()
	h.Write([]byte(host))
	idx := int(h.Sum32()) % len(hostPalette)
	if idx < 0 {
		idx += len(hostPalette)
	}
	return fmt.Sprintf("\033[38;5;%dm", hostPalette[idx])
}

// formatHostPrefix renders a colored, fixed-width host column. If the name
// is longer than the width, alignment is dropped rather than truncated so
// hostnames remain searchable.
func formatHostPrefix(host string) string {
	color := hostColor(host)
	label := host
	if label == "" {
		label = "?"
	}
	if len(label) < 10 {
		label = label + strings.Repeat(" ", 10-len(label))
	}
	return color + "[" + label + "]" + reset
}

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

type printer struct {
	verbose bool
	mu      sync.Mutex // serialises concurrent print() calls across gRPC streams
}

func newPrinter(verbose bool) *printer { return &printer{verbose: verbose} }

// print renders one event. Multiple daemons connect over gRPC and each gets
// its own goroutine in the server, so concurrent print() calls are normal —
// we assemble the whole event (header + req + res + separator) in a single
// buffer and emit it with one os.Stdout.Write to keep lines from different
// events from interleaving on screen.
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

	reqBody := req["body"]
	resBody := res["body"]

	var buf strings.Builder
	fmt.Fprintf(&buf, "%s[%s]%s %s %s  %-6s %s  %s  %5.0fms  %s\n",
		gray, ts, reset,
		formatHostPrefix(e.Host),
		tag,
		method, truncate(path, 60),
		statusStr,
		e.LatencyMs,
		gray+fmt.Sprintf("%s • PID %d", e.Peer, e.PID)+reset,
	)

	if p.verbose {
		// Full, untruncated, pretty-indented bodies.
		fmt.Fprintf(&buf, "  %sreq%s%s\n", gray, reset, prettyIndent(reqBody, -1))
		fmt.Fprintf(&buf, "  %sres%s%s\n", gray, reset, prettyIndent(resBody, -1))
	} else {
		// Default: one-line semantic summary per body so LLM / MCP / A2A
		// responses render with the same density as SSE merged responses.
		fmt.Fprintf(&buf, "  %sreq%s%s\n", gray, reset, renderReq(reqBody))
		fmt.Fprintf(&buf, "  %sres%s%s\n", gray, reset, renderRes(resBody))
	}
	buf.WriteString(strings.Repeat("─", 90))
	buf.WriteByte('\n')

	// Single Write under a mutex: even if stdout is buffered/line-buffered,
	// we guarantee no other goroutine can interleave between header and
	// separator of this event.
	p.mu.Lock()
	_, _ = os.Stdout.WriteString(buf.String())
	p.mu.Unlock()
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

// renderReq returns a one-line default-mode summary for a request body.
// Tries in order: LLM last-user-message, JSON-RPC method+args, fallback
// compact JSON. Goal is parity with SSE responses (also one line).
func renderReq(body any) string {
	if body == nil {
		return "  " + gray + "(empty)" + reset
	}
	if s, ok := body.(string); ok {
		if s == "" {
			return "  " + gray + "(empty)" + reset
		}
		return "  " + fmt.Sprintf("%q", truncate(s, 160))
	}
	m, ok := body.(map[string]any)
	if !ok {
		return "  " + compactAny(body, 140)
	}
	if prompt := extractLLMPrompt(m); prompt != "" {
		extras := llmRequestBadges(m)
		return "  " + fmt.Sprintf("%q", truncate(prompt, 160)) + extras
	}
	if method := jsonRPCMethod(m); method != "" {
		if extra := jsonRPCReqExtra(m); extra != "" {
			return "  " + green + method + reset + "  " + gray + extra + reset
		}
		return "  " + green + method + reset
	}
	return "  " + compactAny(body, 140)
}

// renderRes returns a one-line default-mode summary for a response body.
// Tries in order: SSE merged text, LLM assistant text, tool call,
// provider error, JSON-RPC result summary, fallback compact JSON.
func renderRes(body any) string {
	if body == nil {
		return "  " + gray + "(empty)" + reset
	}
	if s, ok := body.(string); ok {
		if s == "" {
			return "  " + gray + "(empty)" + reset
		}
		return "  " + fmt.Sprintf("%q", truncate(s, 200))
	}
	m, ok := body.(map[string]any)
	if !ok {
		return "  " + compactAny(body, 140)
	}

	// SSE merged shape kept as-is (parity anchor).
	if text, ok := m["text"].(string); ok {
		if _, hasChunks := m["chunks"]; hasChunks {
			suffix := ""
			if chunks, ok := m["chunks"].(float64); ok {
				reason, _ := m["finishReason"].(string)
				if reason != "" {
					suffix = fmt.Sprintf("  %s(%d chunks, %s)%s", gray, int(chunks), reason, reset)
				} else {
					suffix = fmt.Sprintf("  %s(%d chunks)%s", gray, int(chunks), reset)
				}
			}
			return "  " + fmt.Sprintf("%q", truncate(text, 200)) + suffix
		}
	}
	// Provider error.
	if errObj, ok := m["error"].(map[string]any); ok {
		return "  " + red + formatProviderError(errObj) + reset
	}
	// LLM tool call.
	if tc := extractToolCall(m); tc != "" {
		return "  " + cyan + tc + reset
	}
	// LLM assistant text.
	if text := extractLLMText(m); text != "" {
		suffix := ""
		if fr := extractFinishReason(m); fr != "" {
			suffix = fmt.Sprintf("  %s(%s)%s", gray, fr, reset)
		}
		return "  " + fmt.Sprintf("%q", truncate(text, 200)) + suffix
	}
	// JSON-RPC result summary.
	if res, ok := m["result"]; ok {
		return "  " + green + "→" + reset + " " + summarizeJSONRPCResult(res)
	}
	return "  " + compactAny(body, 140)
}

// --- extraction helpers ---

func extractLLMPrompt(m map[string]any) string {
	// Gemini: contents[-1].parts[-1].text
	if contents, ok := m["contents"].([]any); ok && len(contents) > 0 {
		if last, ok := contents[len(contents)-1].(map[string]any); ok {
			if parts, ok := last["parts"].([]any); ok && len(parts) > 0 {
				if lp, ok := parts[len(parts)-1].(map[string]any); ok {
					if t, _ := lp["text"].(string); t != "" {
						return t
					}
				}
			}
		}
	}
	// OpenAI / Anthropic / Ollama: messages[-1].content
	if msgs, ok := m["messages"].([]any); ok && len(msgs) > 0 {
		if last, ok := msgs[len(msgs)-1].(map[string]any); ok {
			switch c := last["content"].(type) {
			case string:
				return c
			case []any:
				// OpenAI multimodal: concat text blocks
				for _, b := range c {
					if bm, ok := b.(map[string]any); ok {
						if t, _ := bm["text"].(string); t != "" {
							return t
						}
					}
				}
			}
		}
	}
	// Ollama completion endpoint
	if p, _ := m["prompt"].(string); p != "" {
		return p
	}
	return ""
}

// llmRequestBadges returns inline annotations for non-text parts of a
// request — tool declarations, image attachments — so users can see the
// request was more than just a prompt without dumping full schemas.
func llmRequestBadges(m map[string]any) string {
	var badges []string
	// Tools declared on the request
	if tools, ok := m["tools"].([]any); ok && len(tools) > 0 {
		names := collectToolNames(tools)
		if len(names) > 0 {
			badges = append(badges, "tools: "+strings.Join(names, ","))
		} else {
			badges = append(badges, fmt.Sprintf("tools: %d", len(tools)))
		}
	}
	// Image / document attachments in the last message
	if contents, ok := m["contents"].([]any); ok && len(contents) > 0 {
		if last, ok := contents[len(contents)-1].(map[string]any); ok {
			if parts, ok := last["parts"].([]any); ok {
				img, doc := countMedia(parts)
				if img > 0 {
					badges = append(badges, fmt.Sprintf("+%dimg", img))
				}
				if doc > 0 {
					badges = append(badges, fmt.Sprintf("+%ddoc", doc))
				}
			}
		}
	}
	if msgs, ok := m["messages"].([]any); ok && len(msgs) > 0 {
		if last, ok := msgs[len(msgs)-1].(map[string]any); ok {
			if c, ok := last["content"].([]any); ok {
				img, doc := countMedia(c)
				if img > 0 {
					badges = append(badges, fmt.Sprintf("+%dimg", img))
				}
				if doc > 0 {
					badges = append(badges, fmt.Sprintf("+%ddoc", doc))
				}
			}
		}
	}
	if len(badges) == 0 {
		return ""
	}
	return "  " + gray + "[" + strings.Join(badges, " ") + "]" + reset
}

func collectToolNames(tools []any) []string {
	var out []string
	for _, t := range tools {
		tm, _ := t.(map[string]any)
		if tm == nil {
			continue
		}
		// Gemini: {functionDeclarations: [{name: "..."}]}
		if fd, ok := tm["functionDeclarations"].([]any); ok {
			for _, f := range fd {
				if fm, _ := f.(map[string]any); fm != nil {
					if n, _ := fm["name"].(string); n != "" {
						out = append(out, n)
					}
				}
			}
			continue
		}
		// OpenAI: {type: "function", function: {name: "..."}}
		if fn, ok := tm["function"].(map[string]any); ok {
			if n, _ := fn["name"].(string); n != "" {
				out = append(out, n)
			}
			continue
		}
		// Anthropic: {name: "...", input_schema: {...}}
		if n, _ := tm["name"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func countMedia(parts []any) (img, doc int) {
	for _, p := range parts {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		if t, _ := pm["type"].(string); t != "" {
			switch t {
			case "image", "image_url":
				img++
			case "document", "file":
				doc++
			}
		}
		if _, has := pm["inlineData"]; has { // Gemini
			img++
		}
	}
	return
}

func extractLLMText(m map[string]any) string {
	// Gemini: candidates[0].content.parts[*].text
	if cands, ok := m["candidates"].([]any); ok && len(cands) > 0 {
		if c0, ok := cands[0].(map[string]any); ok {
			if content, ok := c0["content"].(map[string]any); ok {
				if parts, ok := content["parts"].([]any); ok {
					var b strings.Builder
					for _, p := range parts {
						if po, ok := p.(map[string]any); ok {
							if t, _ := po["text"].(string); t != "" {
								b.WriteString(t)
							}
						}
					}
					if b.Len() > 0 {
						return b.String()
					}
				}
			}
		}
	}
	// OpenAI: choices[0].message.content
	if choices, ok := m["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			if msg, ok := c0["message"].(map[string]any); ok {
				if t, _ := msg["content"].(string); t != "" {
					return t
				}
			}
		}
	}
	// Anthropic: content[0].text
	if content, ok := m["content"].([]any); ok && len(content) > 0 {
		if c0, ok := content[0].(map[string]any); ok {
			if t, _ := c0["text"].(string); t != "" {
				return t
			}
		}
	}
	// Ollama: message.content
	if msg, ok := m["message"].(map[string]any); ok {
		if t, _ := msg["content"].(string); t != "" {
			return t
		}
	}
	return ""
}

func extractToolCall(m map[string]any) string {
	// Gemini: candidates[0].content.parts[*].functionCall
	if cands, ok := m["candidates"].([]any); ok && len(cands) > 0 {
		if c0, ok := cands[0].(map[string]any); ok {
			if content, ok := c0["content"].(map[string]any); ok {
				if parts, ok := content["parts"].([]any); ok {
					for _, p := range parts {
						if po, ok := p.(map[string]any); ok {
							if fc, ok := po["functionCall"].(map[string]any); ok {
								return formatFnCall(fc["name"], fc["args"])
							}
						}
					}
				}
			}
		}
	}
	// OpenAI: choices[0].message.tool_calls[0].function
	if choices, ok := m["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			if msg, ok := c0["message"].(map[string]any); ok {
				if tcs, ok := msg["tool_calls"].([]any); ok && len(tcs) > 0 {
					if tc, ok := tcs[0].(map[string]any); ok {
						if fn, ok := tc["function"].(map[string]any); ok {
							return formatFnCall(fn["name"], fn["arguments"])
						}
					}
				}
			}
		}
	}
	// Anthropic: content[*].type == "tool_use"
	if content, ok := m["content"].([]any); ok {
		for _, c := range content {
			if cm, ok := c.(map[string]any); ok {
				if cm["type"] == "tool_use" {
					return formatFnCall(cm["name"], cm["input"])
				}
			}
		}
	}
	return ""
}

func formatFnCall(name, args any) string {
	n, _ := name.(string)
	if n == "" {
		return ""
	}
	var argsStr string
	switch a := args.(type) {
	case string:
		argsStr = a
	default:
		if b, err := json.Marshal(a); err == nil {
			argsStr = string(b)
		}
	}
	return fmt.Sprintf("→ %s(%s)", n, truncate(argsStr, 120))
}

func extractFinishReason(m map[string]any) string {
	if cands, ok := m["candidates"].([]any); ok && len(cands) > 0 {
		if c0, ok := cands[0].(map[string]any); ok {
			if fr, _ := c0["finishReason"].(string); fr != "" {
				return fr
			}
		}
	}
	if choices, ok := m["choices"].([]any); ok && len(choices) > 0 {
		if c0, ok := choices[0].(map[string]any); ok {
			if fr, _ := c0["finish_reason"].(string); fr != "" {
				return fr
			}
		}
	}
	if fr, _ := m["stop_reason"].(string); fr != "" {
		return fr
	}
	if done, ok := m["done"].(bool); ok && done {
		return "done"
	}
	return ""
}

func formatProviderError(err map[string]any) string {
	var parts []string
	if c, ok := err["code"].(float64); ok {
		parts = append(parts, fmt.Sprintf("%d", int(c)))
	} else if c, _ := err["code"].(string); c != "" {
		parts = append(parts, c)
	}
	if s, _ := err["status"].(string); s != "" {
		parts = append(parts, s)
	}
	if t, _ := err["type"].(string); t != "" {
		parts = append(parts, t)
	}
	out := "error: " + strings.Join(parts, " ")
	if msg, _ := err["message"].(string); msg != "" {
		out += " — " + fmt.Sprintf("%q", truncate(msg, 120))
	}
	return out
}

func jsonRPCMethod(m map[string]any) string {
	if m["jsonrpc"] != "2.0" {
		return ""
	}
	method, _ := m["method"].(string)
	return method
}

func jsonRPCReqExtra(m map[string]any) string {
	params, _ := m["params"].(map[string]any)
	if params == nil {
		return ""
	}
	// Common single-key summaries (id, name).
	if id, _ := params["id"].(string); id != "" {
		return "#" + id
	}
	if n, _ := params["name"].(string); n != "" {
		return n
	}
	return ""
}

func summarizeJSONRPCResult(v any) string {
	m, ok := v.(map[string]any)
	if !ok {
		return compactAny(v, 120)
	}
	// MCP tools/list
	if tools, ok := m["tools"].([]any); ok {
		names := collectToolNames(tools)
		if len(names) > 0 {
			return fmt.Sprintf("%d tools [%s]", len(tools), strings.Join(names, ","))
		}
		return fmt.Sprintf("%d tools", len(tools))
	}
	// MCP initialize
	if pv, _ := m["protocolVersion"].(string); pv != "" {
		return "protocolVersion " + pv
	}
	// A2A status
	if st, ok := m["status"].(map[string]any); ok {
		if s, _ := st["state"].(string); s != "" {
			return "state: " + s
		}
	}
	return compactAny(m, 120)
}

func compactAny(v any, maxLen int) string {
	b, err := json.Marshal(v)
	if err != nil {
		return truncate(fmt.Sprintf("%v", v), maxLen)
	}
	return truncate(string(b), maxLen)
}

// prettyIndent marshals `v` as indented JSON, prefixed so it aligns under
// the `req` / `res` label column. `maxStr` ≥ 0 additionally caps string
// values via truncateStrings; pass -1 to disable.
func prettyIndent(v any, maxStr int) string {
	if maxStr >= 0 {
		v = truncateStrings(v, maxStr)
	}
	b, err := json.MarshalIndent(v, "      ", "  ")
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return "\n      " + string(b)
}

// truncateStrings recursively walks `v` and caps any string value longer
// than `maxLen` with an ellipsis + remaining-byte count marker. Non-string
// leaves are returned unchanged.
func truncateStrings(v any, maxLen int) any {
	switch x := v.(type) {
	case string:
		if len(x) > maxLen {
			return x[:maxLen] + fmt.Sprintf("…(+%d bytes)", len(x)-maxLen)
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = truncateStrings(vv, maxLen)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = truncateStrings(vv, maxLen)
		}
		return out
	}
	return v
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
