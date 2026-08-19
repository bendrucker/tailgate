// Package config loads and validates tailgate's HuJSON configuration.
//
// Reload is a process restart. There is no watcher and no reload path, and none
// should be added: every consumer reads its configuration once at startup and
// holds it for the process lifetime.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
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
	// Favicon is the path to an icon image served at /favicon.ico, along with
	// a root page linking it, so icon crawlers index something for the origin.
	// The path is configuration rather than an embedded asset because the
	// right image is deployment-specific. Empty serves neither path.
	Favicon string `json:"favicon,omitempty"`
}

// Node configures tailgate's embedded Tailscale node and Funnel listener.
type Node struct {
	Hostname string `json:"hostname"`
	StateDir string `json:"state_dir"`
	Port     int    `json:"port"`
	// Tailnet is the MagicDNS suffix the node joins under, such as
	// "example-name.ts.net". Setting it makes every canonical resource URI
	// derivable without contacting the control server, which is what lets the
	// tsidp grant be generated and reviewed before tailgate ever runs. It is
	// also checked against the name the join actually reports, so a node that
	// lands on a different name than the grant was written for fails to serve
	// rather than serving URIs no grant covers.
	Tailnet string `json:"tailnet,omitempty"`
}

// FQDN reports the tailnet DNS name the node is expected to join under, or the
// empty string when the config does not name a tailnet.
func (n Node) FQDN() string {
	if n.Tailnet == "" {
		return ""
	}
	return n.Hostname + "." + n.Tailnet
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
// field equals the corresponding claim from token introspection. tsidp's
// introspection response carries sub, username, scope, and email (the last
// only when the token was granted the email scope), so arbitrary claim
// matches are limited to those until tsidp exposes extra claims there, and
// email rules require clients to request the email scope.
type Match struct {
	Subject string            `json:"sub,omitempty"`
	Email   string            `json:"email,omitempty"`
	Claim   map[string]string `json:"claim,omitempty"`
}

// empty reports whether the match has no conditions. An empty match would
// vacuously allow every identity, so validation rejects it.
func (m *Match) empty() bool {
	if m.Subject != "" || m.Email != "" {
		return false
	}
	for k, v := range m.Claim {
		if k != "" && v != "" {
			return false
		}
	}
	return true
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
	// Unknown fields are errors, never silently dropped: a typoed or removed
	// policy key that decodes to an empty match would fail open.
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
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
	// The suffix joins the hostname to form a bare host, so anything that
	// would make the result something other than one host would mint resource
	// URIs no grant could match.
	if c.Node.Tailnet != "" && strings.ContainsAny(c.Node.Tailnet, "/:?# ") {
		return fmt.Errorf("config: node.tailnet %q must be a bare DNS suffix", c.Node.Tailnet)
	}

	names := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("config: upstream name is required")
		}
		// The name becomes a single path segment of the canonical resource
		// URI, matched byte-for-byte against grants and routes. Anything
		// outside this set (slashes, dots, URL metacharacters, uppercase)
		// would mint an aliased, unroutable, or divergently escaped URI.
		if !upstreamName.MatchString(u.Name) {
			return fmt.Errorf("config: upstream name %q must match %s", u.Name, upstreamName)
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
		if len(r.Allow) == 0 {
			return fmt.Errorf("config: policy for %q has no allow conditions", r.Upstream)
		}
		for _, m := range r.Allow {
			if m.empty() {
				return fmt.Errorf("config: policy for %q has an empty allow condition, which would match every identity", r.Upstream)
			}
		}
	}
	return nil
}

// upstreamName restricts names to lowercase DNS-label-like segments.
var upstreamName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

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
