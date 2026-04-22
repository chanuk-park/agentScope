package daemon

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

var validCommTypes = map[string]struct{}{
	"Agent↔Model": {},
	"Agent↔Agent": {},
	"Agent↔MCP":   {},
	"Unknown":     {},
}

// Config is the YAML schema; see agentscope.yaml.sample for usage. LLM lists merge on top of detector.go builtins.
type Config struct {
	Peers               map[string]string `yaml:"peers"`
	LLMHostnames        []string          `yaml:"llm_hostnames"`
	LLMHostnamePatterns []string          `yaml:"llm_hostname_patterns"`
	LLMHTTPPaths        []string          `yaml:"llm_http_paths"`
}

// LoadConfigFile returns (nil, nil) for ENOENT — config is optional.
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

// ParsePeerFlags: repeated `-peer k=v` → map; later flag wins on conflict.
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

// BuildPeerOverrides merges YAML peers + CLI -peer flags (CLI wins).
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
			merged[k] = v
		}
	}

	for peer, typ := range merged {
		log.Printf("config: peer override %q → %s", peer, typ)
	}
	return merged, nil
}

// peerListFlag: flag.Value implementation so `-peer k=v` can repeat.
type peerListFlag []string

func (p *peerListFlag) String() string     { return strings.Join(*p, ",") }
func (p *peerListFlag) Set(s string) error { *p = append(*p, s); return nil }

func NewPeerListFlag(backing *[]string) *peerListFlag {
	return (*peerListFlag)(backing)
}
