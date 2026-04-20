package daemon

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Valid comm-type labels accepted in peer overrides.
var validCommTypes = map[string]struct{}{
	"Agent↔Model": {},
	"Agent↔Agent": {},
	"Agent↔MCP":   {},
	"Unknown":     {},
}

// Config is the on-disk YAML schema.
//
//   peers:
//     "10.0.0.2:8080":      "Agent↔Agent"
//     "ollama.local:11434": "Agent↔Model"
//     "my-mcp-server:3000": "Agent↔MCP"
//
//   llm_hostnames: ["api.openai.com", "api.anthropic.com"]
//   llm_hostname_patterns: ["*.openai.azure.com", "bedrock-runtime.*.amazonaws.com"]
//   llm_http_paths: ["POST /v1/chat/completions", "POST /api/generate"]
//
// Peers map keys may be full `host:port` or bare `host` (the classifier
// checks both). LLM lists are merged on top of the built-in defaults from
// detector.go — operators add to, never replace, the baked-in list.
type Config struct {
	Peers               map[string]string `yaml:"peers"`
	LLMHostnames        []string          `yaml:"llm_hostnames"`
	LLMHostnamePatterns []string          `yaml:"llm_hostname_patterns"`
	LLMHTTPPaths        []string          `yaml:"llm_http_paths"`
}

// LoadConfigFile reads a YAML config from path. If the file does not exist,
// returns (nil, nil) — configuration is optional. Malformed YAML or
// unknown comm types surface as errors.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	for peer, typ := range cfg.Peers {
		if _, ok := validCommTypes[typ]; !ok {
			return nil, fmt.Errorf("%s: peer %q has unknown comm type %q (want Agent↔Model|Agent↔Agent|Agent↔MCP|Unknown)", path, peer, typ)
		}
	}
	return &cfg, nil
}

// ParsePeerFlags converts repeated `-peer k=v` CLI values into a map.
// Overrides a previous entry with the same key — later flag wins.
func ParsePeerFlags(pairs []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range pairs {
		eq := strings.IndexByte(p, '=')
		if eq <= 0 || eq == len(p)-1 {
			return nil, fmt.Errorf("-peer %q: expected <peer>=<type>", p)
		}
		key := strings.TrimSpace(p[:eq])
		typ := strings.TrimSpace(p[eq+1:])
		if _, ok := validCommTypes[typ]; !ok {
			return nil, fmt.Errorf("-peer %q: unknown comm type %q", p, typ)
		}
		out[key] = typ
	}
	return out, nil
}

// BuildPeerOverrides loads the YAML config (if present) and merges CLI
// -peer overrides on top — CLI wins on conflict. Returns a merged map
// and logs what was loaded so operators can confirm visually.
func BuildPeerOverrides(configPath string, cliPairs []string) (map[string]string, error) {
	merged := map[string]string{}

	cfg, err := LoadConfigFile(configPath)
	if err != nil {
		return nil, err
	}
	if cfg != nil && len(cfg.Peers) > 0 {
		log.Printf("config: loaded %d peer overrides from %s", len(cfg.Peers), configPath)
		for k, v := range cfg.Peers {
			merged[k] = v
		}
	}

	cli, err := ParsePeerFlags(cliPairs)
	if err != nil {
		return nil, err
	}
	if len(cli) > 0 {
		log.Printf("config: %d peer overrides from -peer flag", len(cli))
		for k, v := range cli {
			merged[k] = v // CLI wins
		}
	}

	for peer, typ := range merged {
		log.Printf("config: peer override %q → %s", peer, typ)
	}
	return merged, nil
}

// peerListFlag implements flag.Value so `-peer k=v` can repeat.
type peerListFlag []string

func (p *peerListFlag) String() string     { return strings.Join(*p, ",") }
func (p *peerListFlag) Set(s string) error { *p = append(*p, s); return nil }

// NewPeerListFlag returns a flag.Value suitable for flag.Var registration.
func NewPeerListFlag(backing *[]string) *peerListFlag {
	return (*peerListFlag)(backing)
}
