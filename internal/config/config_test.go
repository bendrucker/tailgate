package config

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// ownerOnlyCopy stages a config file at a mode Load accepts. The golden file
// lives in testdata, where a checkout gives it the world-readable mode Load
// refuses.
func ownerOnlyCopy(t *testing.T, source string) string {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read %s: %v", source, err)
	}
	path := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoad(t *testing.T) {
	got, err := Load(ownerOnlyCopy(t, "testdata/tailgate.hujson"))
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

// TestValidateRejectsUnevaluableClaimCondition covers a claim condition that
// sits beside a real one, so the rule reads as an allowance while the empty
// name or value it carries matches no identity.
func TestValidateRejectsUnevaluableClaimCondition(t *testing.T) {
	for _, tc := range []struct {
		name  string
		match Match
	}{
		{
			name:  "empty claim name beside a subject",
			match: Match{Subject: "42", Claim: map[string]string{"": "value"}},
		},
		{
			name:  "empty claim value beside an email",
			match: Match{Email: "ben@example.com", Claim: map[string]string{"username": ""}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Node:      Node{Hostname: "tailgate", Port: 443},
				OIDC:      OIDC{Issuer: "https://idp.tail-scale.ts.net"},
				Upstreams: []Upstream{{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
				Policy:    []Rule{{Upstream: "github", Allow: []Match{tc.match}}},
			}
			if err := c.Validate(); err == nil {
				t.Fatal("expected error for a claim condition no identity can match")
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

func TestValidateNodeTags(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tags    []string
		wantErr bool
	}{
		{name: "no tags"},
		{name: "one tag", tags: []string{"tag:tailgate"}},
		{name: "several tags", tags: []string{"tag:tailgate", "tag:mcp"}},
		{name: "a tag without its prefix", tags: []string{"tailgate"}, wantErr: true},
		{name: "a bare prefix names nothing", tags: []string{"tag:"}, wantErr: true},
		{name: "an empty entry", tags: []string{""}, wantErr: true},
		{name: "one bad tag among good ones", tags: []string{"tag:tailgate", "mcp"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Node: Node{Hostname: "tailgate", Port: 443, Tags: tc.tags},
				OIDC: OIDC{Issuer: "https://idp.tail-scale.ts.net"},
			}
			if err := c.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateStdioCredential covers the uid a stdio child runs under. Zero
// spells unset rather than root, so a half-set pair has to be refused: a child
// keeping tailgate's uid contains nothing, and one whose gid falls through to
// zero runs in the root group.
func TestValidateStdioCredential(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream Upstream
		wantErr  bool
	}{
		{
			name:     "stdio without a credential",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files"},
		},
		{
			name:     "stdio with a uid and gid",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570, GID: 570},
		},
		{
			name:     "stdio uid without a gid",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio gid without a uid",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", GID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio negative uid",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: -1, GID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio negative gid",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570, GID: -1},
			wantErr:  true,
		},
		{
			name:     "stdio uid past a uid_t",
			upstream: Upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: math.MaxUint32 + 1, GID: 570},
			wantErr:  true,
		},
		{
			name:     "http upstream with a uid",
			upstream: Upstream{Name: "files", Transport: TransportHTTP, URL: "http://127.0.0.1:9000/mcp", UID: 570, GID: 570},
			wantErr:  true,
		},
		{
			name:     "http upstream without one",
			upstream: Upstream{Name: "files", Transport: TransportHTTP, URL: "http://127.0.0.1:9000/mcp"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Config{
				Node:      Node{Hostname: "tailgate", Port: 443},
				OIDC:      OIDC{Issuer: "https://idp.tail-scale.ts.net"},
				Upstreams: []Upstream{tc.upstream},
			}
			if err := c.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
