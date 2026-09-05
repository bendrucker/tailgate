// Package config loads and validates tailgate's HuJSON configuration.
//
// Load returns values every consumer uses as they are: an upstream's URL is a
// *url.URL, its idle timeout a time.Duration, and its credential nil when the
// file sets none. Nothing downstream parses a configuration string a second
// time, so a value that cannot be parsed fails the load rather than the router
// assembly that follows it. A SIGHUP reload runs the same load, which is why
// the two must not disagree about what a valid file is.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/tailscale/hujson"
)

// funnelPorts are the only TCP ports Tailscale Funnel supports.
var funnelPorts = map[int]bool{443: true, 8443: true, 10000: true}

// FunnelPort refuses a port Tailscale Funnel does not serve. Funnel is
// tailgate's only exposure, so a listener on any other port comes up locally
// and is then unreachable from the internet. The caller names whatever it was
// handed the port as, since the same rule covers the config key and the node
// the key configures.
func FunnelPort(port int) error {
	if !funnelPorts[port] {
		return fmt.Errorf("port %d is not a Funnel port (443, 8443, 10000)", port)
	}
	return nil
}

// OwnerOnly refuses filesystem state readable beyond its owner. holds names
// what is at stake, which is what makes the refusal actionable in a log nobody
// is watching: under launchd there is no one reading startup output, so a
// warning would do nothing.
func OwnerOnly(name string, mode fs.FileMode, holds string) error {
	if perm := mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s is mode %#o, readable beyond its owner, and it holds %s", name, perm, holds)
	}
	return nil
}

// Config is the parsed tailgate configuration.
type Config struct {
	Node      Node
	Upstreams []Upstream
	Policy    []Rule
	// Favicon is the path to an icon image served at /favicon.ico, along with
	// a root page linking it, so icon crawlers index something for the origin.
	// The path is configuration rather than an embedded asset because the
	// right image is deployment-specific. Empty serves neither path.
	Favicon string
}

// document is the configuration file's own shape, decoded before anything is
// parsed. It exists for the fields no consumer may hold as the file spells
// them: an upstream's url, idle_timeout, uid, and gid arrive here as strings
// and integers and leave as a *url.URL, a time.Duration, and a *Credential.
// Node, Rule, and Match carry nothing to parse, so they are decoded as they
// are and keep the tags naming their keys, which a refused reload reports.
type document struct {
	Node      Node       `json:"node"`
	Upstreams []upstream `json:"upstreams"`
	Policy    []Rule     `json:"policy"`
	Favicon   string     `json:"favicon,omitempty"`
}

// Node configures tailgate's embedded Tailscale node and Funnel listener.
type Node struct {
	Hostname string `json:"hostname"`
	StateDir string `json:"state_dir"`
	Port     int    `json:"port"`
	// Tailnet is the MagicDNS suffix the node joins under, such as
	// "example-name.ts.net". Setting it pins the name the node must join
	// under. Every canonical resource URI is built from that name, and a
	// client's tokens carry it as their audience, so a node that lands on a
	// different name fails to serve.
	Tailnet string `json:"tailnet,omitempty"`

	// Tags are the ACL tags the node advertises when it joins, such as
	// "tag:tailgate". Setting them here puts the node's tailnet identity in the
	// config a reviewer reads, rather than leaving it implicit in whichever
	// auth key happened to mint the node. The control server still decides
	// whether the node may adopt a tag it advertises.
	Tags []string `json:"tags,omitempty"`
}

// FQDN reports the tailnet DNS name the node is expected to join under, or the
// empty string when the config does not name a tailnet.
func (n Node) FQDN() string {
	if n.Tailnet == "" {
		return ""
	}
	return n.Hostname + "." + n.Tailnet
}

func (n Node) validate() error {
	if n.Hostname == "" {
		return fmt.Errorf("config: node.hostname is required")
	}
	if err := FunnelPort(n.Port); err != nil {
		return fmt.Errorf("config: node.port: %w", err)
	}
	// The suffix joins the hostname to form a bare host, so anything that
	// would make the result something other than one host would mint resource
	// URIs no client could be configured with.
	if n.Tailnet != "" && strings.ContainsAny(n.Tailnet, "/:?# ") {
		return fmt.Errorf("config: node.tailnet %q must be a bare DNS suffix", n.Tailnet)
	}
	for _, tag := range n.Tags {
		// A tag the control server rejects leaves the node joined and untagged
		// rather than failing the join, so a typo here is invisible at runtime.
		if !strings.HasPrefix(tag, "tag:") || tag == "tag:" {
			return fmt.Errorf("config: node.tags entry %q must be of the form tag:<name>", tag)
		}
	}
	return nil
}

// Rule allows matching identities to reach one upstream.
type Rule struct {
	Upstream string  `json:"upstream"`
	Allow    []Match `json:"allow"`
}

// Match is a single allow condition. An identity matches when every non-empty
// field equals the corresponding claim on the token. A token carries sub (the
// tailnet user's decimal ID), email (the login name), name, scope, client_id,
// and aud, so arbitrary claim matches are limited to those.
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

// unevaluable reports whether the match states a claim condition authorization
// cannot evaluate. An empty name or value matches no identity, so a rule
// carrying one is dead policy: it reads as a granted allowance and denies
// everyone it names.
func (m *Match) unevaluable() bool {
	for k, v := range m.Claim {
		if k == "" || v == "" {
			return true
		}
	}
	return false
}

// Load reads, parses, and validates the config file at path.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// The mode is read from the open file rather than the path, so the bytes
	// parsed below are the bytes that were checked.
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("config: stat %s: %w", path, err)
	}
	// This is the one file that concentrates every upstream's credentials, and
	// the documented location is a system path where the naive mode is
	// world-readable.
	if err := OwnerOnly(path, info.Mode(), "every upstream's credentials"); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return LoadReader(file)
}

// LoadReader parses and validates a configuration document. The mode check
// Load makes belongs to a path, so a caller reading the document from anywhere
// else is responsible for how it got there.
func LoadReader(r io.Reader) (*Config, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	std, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("config: parse hujson: %w", err)
	}
	var doc document
	// Unknown fields are errors, never silently dropped: a typoed or removed
	// policy key that decodes to an empty match would fail open.
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	return doc.parse()
}

// parse turns the decoded file into the configuration tailgate serves,
// rejecting anything a consumer could not act on.
func (d *document) parse() (*Config, error) {
	if err := d.Node.validate(); err != nil {
		return nil, err
	}
	cfg := &Config{Node: d.Node, Policy: d.Policy, Favicon: d.Favicon}

	names := make(map[string]bool, len(d.Upstreams))
	for _, u := range d.Upstreams {
		parsed, err := u.parse()
		if err != nil {
			return nil, err
		}
		if names[parsed.Name] {
			return nil, fmt.Errorf("config: duplicate upstream %q", parsed.Name)
		}
		names[parsed.Name] = true
		cfg.Upstreams = append(cfg.Upstreams, parsed)
	}

	for _, r := range d.Policy {
		if !names[r.Upstream] {
			return nil, fmt.Errorf("config: policy references unknown upstream %q", r.Upstream)
		}
		if len(r.Allow) == 0 {
			return nil, fmt.Errorf("config: policy for %q has no allow conditions", r.Upstream)
		}
		for _, m := range r.Allow {
			if m.empty() {
				return nil, fmt.Errorf("config: policy for %q has an empty allow condition, which would match every identity", r.Upstream)
			}
			if m.unevaluable() {
				return nil, fmt.Errorf("config: policy for %q has a claim condition with an empty name or value, which no identity can match", r.Upstream)
			}
		}
	}
	return cfg, nil
}

// upstreamName restricts names to lowercase DNS-label-like segments.
var upstreamName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
