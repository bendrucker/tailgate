package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestLoad(t *testing.T) {
	got, err := Load("testdata/tailgate.hujson")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := &Config{
		Node: Node{Hostname: "tailgate", StateDir: "/var/lib/tailgate", Port: 443},
		OIDC: OIDC{Issuer: "https://idp.tail-scale.ts.net"},
		Upstreams: []Upstream{
			{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"},
		},
		Policy: []Rule{
			{Upstream: "github", Allow: []Match{{Email: "ben@tail-scale.ts.net"}}},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

func TestValidateRejectsNonFunnelPort(t *testing.T) {
	c := &Config{
		Node: Node{Hostname: "tailgate", Port: 8080},
		OIDC: OIDC{Issuer: "https://idp.tail-scale.ts.net"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for non-Funnel port")
	}
}

func TestValidateRejectsUnknownPolicyUpstream(t *testing.T) {
	c := &Config{
		Node:   Node{Hostname: "tailgate", Port: 443},
		OIDC:   OIDC{Issuer: "https://idp.tail-scale.ts.net"},
		Policy: []Rule{{Upstream: "ghost"}},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for policy referencing unknown upstream")
	}
}

func TestValidateRejectsFailOpenPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow []Match
	}{
		{
			name:  "no allow conditions",
			allow: nil,
		},
		{
			name:  "empty match",
			allow: []Match{{}},
		},
		{
			name:  "empty match alongside a real one",
			allow: []Match{{Email: "ben@example.com"}, {}},
		},
		{
			name:  "claim with empty value only",
			allow: []Match{{Claim: map[string]string{"scope": ""}}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Node:      Node{Hostname: "tailgate", Port: 443},
				OIDC:      OIDC{Issuer: "https://idp.tail-scale.ts.net"},
				Upstreams: []Upstream{{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
				Policy:    []Rule{{Upstream: "github", Allow: tc.allow}},
			}
			if err := c.Validate(); err == nil {
				t.Fatal("expected error for allow-all policy shape")
			}
		})
	}
}

func TestValidateRejectsUpstreamName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
	}{
		{name: "path traversal", upstream: ".."},
		{name: "embedded slash", upstream: "a/b"},
		{name: "query metachar", upstream: "a?b"},
		{name: "fragment metachar", upstream: "a#b"},
		{name: "uppercase", upstream: "Github"},
		{name: "leading hyphen", upstream: "-github"},
		{name: "trailing hyphen", upstream: "github-"},
		{name: "space", upstream: "git hub"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Node:      Node{Hostname: "tailgate", Port: 443},
				OIDC:      OIDC{Issuer: "https://idp.tail-scale.ts.net"},
				Upstreams: []Upstream{{Name: tc.upstream, Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
			}
			if err := c.Validate(); err == nil {
				t.Fatalf("expected error for upstream name %q", tc.upstream)
			}
		})
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A removed or typoed policy key must fail loudly: silently dropping it
	// would leave an empty match that allows every identity.
	raw := `{
		"node": {"hostname": "tailgate", "state_dir": "/tmp", "port": 443},
		"oidc": {"issuer": "https://idp.tail-scale.ts.net"},
		"upstreams": [{"name": "github", "transport": "http", "url": "http://127.0.0.1:9000/mcp"}],
		"policy": [{"upstream": "github", "allow": [{"group": "eng"}]}],
	}`
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown policy key")
	}
}
