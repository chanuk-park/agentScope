package daemon

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
)

// agentRuntimes are process comm names that commonly host AI agents. A PID
// whose /proc/<pid>/comm matches one of these AND that has an LLM API key
// environment variable is considered an agent.
var agentRuntimes = [][]byte{
	[]byte("python"), []byte("python3"), []byte("python3.10"),
	[]byte("python3.11"), []byte("python3.12"), []byte("python3.13"),
	[]byte("node"), []byte("deno"), []byte("bun"),
	[]byte("ruby"), []byte("java"),
}

// agentEnvKeys are environment variable prefixes that signal an LLM agent.
var agentEnvKeys = [][]byte{
	[]byte("OPENAI_API_KEY="),
	[]byte("ANTHROPIC_API_KEY="),
	[]byte("GOOGLE_API_KEY="),
	[]byte("GEMINI_API_KEY="),
	[]byte("COHERE_API_KEY="),
	[]byte("GROQ_API_KEY="),
	[]byte("MISTRAL_API_KEY="),
	[]byte("XAI_API_KEY="),
	[]byte("DEEPSEEK_API_KEY="),
	[]byte("AZURE_OPENAI_API_KEY="),
	[]byte("AGENTSCOPE_AGENT=1"), // opt-in marker for processes without API keys
}

// agentCmdlineMarkers catch agent frameworks even when the API key is provided
// out-of-band (config file, vault, etc.).
var agentCmdlineMarkers = [][]byte{
	[]byte("langchain"), []byte("llama_index"), []byte("llamaindex"),
	[]byte("crewai"), []byte("autogen"), []byte("agentscope"),
	[]byte("openai"), []byte("anthropic"),
}

type pidScanner struct {
	m        *ebpf.Map
	p        *parser // parser receives eviction for dead PIDs
	interval time.Duration
	tracked  map[uint32]struct{}
}

func newPIDScanner(m *ebpf.Map, p *parser, interval time.Duration) *pidScanner {
	return &pidScanner{m: m, p: p, interval: interval, tracked: map[uint32]struct{}{}}
}

func (s *pidScanner) run(stop <-chan struct{}) {
	// Prime the map immediately so early traffic isn't missed.
	s.sync()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.sync()
		}
	}
}

func (s *pidScanner) sync() {
	current := scanAgents()
	added, removed := 0, 0
	for pid := range current {
		if _, ok := s.tracked[pid]; ok {
			continue
		}
		one := uint8(1)
		if err := s.m.Put(pid, one); err != nil {
			continue
		}
		s.tracked[pid] = struct{}{}
		added++
	}
	for pid := range s.tracked {
		if _, ok := current[pid]; ok {
			continue
		}
		_ = s.m.Delete(pid)
		delete(s.tracked, pid)
		removed++
		if s.p != nil {
			s.p.evictPID(pid)
		}
	}
	if added > 0 || removed > 0 {
		log.Printf("agent filter: tracked=%d (+%d -%d)", len(s.tracked), added, removed)
	}
}

func scanAgents() map[uint32]struct{} {
	out := map[uint32]struct{}{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		n, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(n)
		if isAgentProcess(pid) {
			out[pid] = struct{}{}
		}
	}
	return out
}

func isAgentProcess(pid uint32) bool {
	base := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))

	comm, err := os.ReadFile(filepath.Join(base, "comm"))
	if err != nil {
		return false
	}
	comm = bytes.TrimSpace(comm)
	if !matchesAny(comm, agentRuntimes) {
		return false
	}

	env, err := os.ReadFile(filepath.Join(base, "environ"))
	if err == nil && containsAny(env, agentEnvKeys) {
		return true
	}

	cmdline, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err == nil && containsAny(cmdline, agentCmdlineMarkers) {
		return true
	}
	return false
}

func matchesAny(b []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Equal(b, n) {
			return true
		}
	}
	return false
}

func containsAny(b []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(b, n) {
			return true
		}
	}
	return false
}
