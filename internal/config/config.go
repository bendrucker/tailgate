// Package config loads and validates tailgate's HuJSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/tailscale/hujson"
)

// Transport names the wire protocol tailgate uses to reach an upstream.
const (
	TransportHTTP  = "http"
	TransportStdio = "stdio"
)

// funnelPorts are the only TCP ports Tailscale Funnel supports.
var funnelPorts = map[int]bool{443: true, 8443: true, 10000: true}

// Config is the parsed tailgate configuration.
type Config struct {
	Node      Node       `json:"node"`
	OIDC      OIDC       `json:"oidc"`
	Upstreams []Upstream `json:"upstreams"`
	Policy    []Rule     `json:"policy"`
}

// Node configures tailgate's embedded Tailscale node and Funnel listener.
type Node struct {
	Hostname string `json:"hostname"`
	StateDir string `json:"state_dir"`
	Port     int    `json:"port"`
}

// OIDC configures the tsidp issuer whose tokens tailgate validates.
type OIDC struct {
	Issuer string `json:"issuer"`
}

// Upstream is one MCP server tailgate fronts, addressed at /mcp/<name>.
type Upstream struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`

	// HTTP transport.
	URL string `json:"url,omitempty"`

	// Stdio transport.
	Command     string   `json:"command,omitempty"`
	Args        []string `json:"args,omitempty"`
	Env         []string `json:"env,omitempty"`
	Dir         string   `json:"dir,omitempty"`
	MaxChildren int      `json:"max_children,omitempty"`
	IdleTimeout string   `json:"idle_timeout,omitempty"`
}

// Rule allows matching identities to reach one upstream.
type Rule struct {
	Upstream string  `json:"upstream"`
	Allow    []Match `json:"allow"`
}

// Match is a single allow condition. An identity matches when every non-empty
// field equals the corresponding token claim.
type Match struct {
	Subject string            `json:"sub,omitempty"`
	Email   string            `json:"email,omitempty"`
	Group   string            `json:"group,omitempty"`
	Claim   map[string]string `json:"claim,omitempty"`
}

// Load reads, parses, and validates the config file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("config: parse hujson: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(std, &cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate reports whether the config is internally consistent.
func (c *Config) Validate() error {
	if c.Node.Hostname == "" {
		return fmt.Errorf("config: node.hostname is required")
	}
	if !funnelPorts[c.Node.Port] {
		return fmt.Errorf("config: node.port %d is not a Funnel port (443, 8443, 10000)", c.Node.Port)
	}
	if c.OIDC.Issuer == "" {
		return fmt.Errorf("config: oidc.issuer is required")
	}

	names := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("config: upstream name is required")
		}
		if names[u.Name] {
			return fmt.Errorf("config: duplicate upstream %q", u.Name)
		}
		names[u.Name] = true
		if err := u.validate(); err != nil {
			return err
		}
	}

	for _, r := range c.Policy {
		if !names[r.Upstream] {
			return fmt.Errorf("config: policy references unknown upstream %q", r.Upstream)
		}
	}
	return nil
}

func (u *Upstream) validate() error {
	switch u.Transport {
	case TransportHTTP:
		if u.URL == "" {
			return fmt.Errorf("config: upstream %q: url is required for http transport", u.Name)
		}
	case TransportStdio:
		if u.Command == "" {
			return fmt.Errorf("config: upstream %q: command is required for stdio transport", u.Name)
		}
		if u.IdleTimeout != "" {
			if _, err := time.ParseDuration(u.IdleTimeout); err != nil {
				return fmt.Errorf("config: upstream %q: idle_timeout: %w", u.Name, err)
			}
		}
	default:
		return fmt.Errorf("config: upstream %q: unknown transport %q", u.Name, u.Transport)
	}
	return nil
}
