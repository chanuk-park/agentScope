package master

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	reset  = "\033[0m"
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
	tag := map[string]string{
		"Agent↔Model": blue + "Agent↔Model" + reset,
		"Agent↔Agent": yellow + "Agent↔Agent" + reset,
		"Agent↔MCP":   green + "Agent↔MCP  " + reset,
	}[e.CommType]

	dir := gray + "→ send" + reset
	if e.Direction == "recv" {
		dir = cyan + "← recv" + reset
	}

	fmt.Printf("%s[%s]%s %s  %s  %-10s  %-25s  %6.0fms  PID:%-6d  Host:%s\n",
		gray, ts, reset,
		tag, dir, e.ContentType, e.Peer, e.LatencyMs, e.PID, e.Host)

	if p.verbose {
		fmt.Printf("  %sREQ:%s %s\n", gray, reset, pretty(e.Request))
		fmt.Printf("  %sRES:%s %s\n", gray, reset, pretty(e.Response))
	} else {
		fmt.Printf("  %sREQ:%s %s\n", gray, reset, truncate(e.Request, 120))
		fmt.Printf("  %sRES:%s %s\n", gray, reset, truncate(e.Response, 120))
	}
	fmt.Println(strings.Repeat("─", 90))
}

func pretty(s string) string {
	var v any
	if json.Unmarshal([]byte(s), &v) != nil {
		return s
	}
	b, _ := json.MarshalIndent(v, "        ", "  ")
	return "\n        " + string(b)
}

func truncate(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
