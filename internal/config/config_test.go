package config

import (
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", raw, err)
	}
	return parsed
}

func TestLoad(t *testing.T) {
	got, err := Load(ownerOnlyCopy(t, "testdata/tailgate.hujson"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := &Config{
		Node: Node{Hostname: "tailgate", StateDir: "/var/lib/tailgate", Port: 443},
		Upstreams: []Upstream{
			{Name: "github", Transport: "http", URL: mustParseURL(t, "http://127.0.0.1:9000/mcp")},
		},
		Policy: []Rule{
			{Upstream: "github", Allow: []Match{{Email: "ben@tail-scale.ts.net"}}},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Load mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadReaderParsesStdio covers the values a stdio upstream reaches its
// transport with, which are the ones no consumer parses a second time.
func TestLoadReaderParsesStdio(t *testing.T) {
	got, err := LoadReader(strings.NewReader(`{
		"node": {"hostname": "tailgate", "port": 443},
		"upstreams": [{
			"name": "files",
			"transport": "stdio",
			"command": "mcp-files",
			"args": ["--root", "/srv"],
			"max_children": 2,
			"idle_timeout": "90s",
			"uid": 570,
			"gid": 570,
		}],
	}`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	want := []Upstream{{
		Name:        "files",
		Transport:   TransportStdio,
		Command:     "mcp-files",
		Args:        []string{"--root", "/srv"},
		MaxChildren: 2,
		IdleTimeout: 90 * time.Second,
		Credential:  &Credential{UID: 570, GID: 570},
	}}
	if diff := cmp.Diff(want, got.Upstreams); diff != "" {
		t.Errorf("upstreams mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadReaderAcceptsHuJSON covers the comments and trailing commas the
// format allows, which are what an operator's file actually looks like.
func TestLoadReaderAcceptsHuJSON(t *testing.T) {
	cfg, err := LoadReader(strings.NewReader(`{
		// the node this tailgate joins as
		"node": {"hostname": "tailgate", "port": 8443},
	}`))
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if cfg.Node.Port != 8443 {
		t.Errorf("expected port 8443, got %d", cfg.Node.Port)
	}
}

func TestLoadReaderRejects(t *testing.T) {
	for _, tc := range []struct {
		name     string
		document string
		reason   string
	}{
		{
			name:     "unclosed document",
			document: `{"node": `,
			reason:   "parse hujson",
		},
		{
			// A removed or typoed policy key must fail loudly: silently
			// dropping it would leave an empty match allowing every identity.
			name: "unknown policy key",
			document: `{
				"node": {"hostname": "tailgate", "port": 443},
				"upstreams": [{"name": "github", "transport": "http", "url": "http://127.0.0.1:9000/mcp"}],
				"policy": [{"upstream": "github", "allow": [{"group": "eng"}]}],
			}`,
			reason: "unmarshal",
		},
		{
			name:     "unknown top level key",
			document: `{"node": {"hostname": "tailgate", "port": 443}, "oidc": {}}`,
			reason:   "unmarshal",
		},
		{
			name:     "port as a string",
			document: `{"node": {"hostname": "tailgate", "port": "443"}}`,
			reason:   "unmarshal",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadReader(strings.NewReader(tc.document))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %q does not name %q", err, tc.reason)
			}
		})
	}
}

func TestParseRejectsNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		node Node
	}{
		{
			name: "no hostname",
			node: Node{Port: 443},
		},
		{
			name: "a port Funnel does not serve",
			node: Node{Hostname: "tailgate", Port: 8080},
		},
		{
			name: "a tailnet that is not a bare suffix",
			node: Node{Hostname: "tailgate", Port: 443, Tailnet: "https://example.ts.net"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document{Node: tc.node}
			if _, err := d.parse(); err == nil {
				t.Fatalf("expected an error for %+v", tc.node)
			}
		})
	}
}

func TestParseRejectsUnknownPolicyUpstream(t *testing.T) {
	d := document{
		Node:   Node{Hostname: "tailgate", Port: 443},
		Policy: []Rule{{Upstream: "ghost"}},
	}
	if _, err := d.parse(); err == nil {
		t.Fatal("expected error for policy referencing unknown upstream")
	}
}

func TestParseRejectsDuplicateUpstream(t *testing.T) {
	d := document{
		Node: Node{Hostname: "tailgate", Port: 443},
		Upstreams: []upstream{
			{Name: "github", Transport: TransportHTTP, URL: "http://127.0.0.1:9000/mcp"},
			{Name: "github", Transport: TransportHTTP, URL: "http://127.0.0.1:9001/mcp"},
		},
	}
	if _, err := d.parse(); err == nil {
		t.Fatal("expected error for a duplicate upstream name")
	}
}

func TestParseRejectsFailOpenPolicy(t *testing.T) {
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
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
				Policy:    []Rule{{Upstream: "github", Allow: tc.allow}},
			}
			if _, err := d.parse(); err == nil {
				t.Fatal("expected error for allow-all policy shape")
			}
		})
	}
}

// TestParseRejectsUnevaluableClaimCondition covers a claim condition that sits
// beside a real one, so the rule reads as an allowance while the empty name or
// value it carries matches no identity.
func TestParseRejectsUnevaluableClaimCondition(t *testing.T) {
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
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{{Name: "github", Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
				Policy:    []Rule{{Upstream: "github", Allow: []Match{tc.match}}},
			}
			if _, err := d.parse(); err == nil {
				t.Fatal("expected error for a claim condition no identity can match")
			}
		})
	}
}

func TestParseRejectsUpstreamName(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream string
	}{
		{name: "empty", upstream: ""},
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
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{{Name: tc.upstream, Transport: "http", URL: "http://127.0.0.1:9000/mcp"}},
			}
			if _, err := d.parse(); err == nil {
				t.Fatalf("expected error for upstream name %q", tc.upstream)
			}
		})
	}
}

func TestParseNodeTags(t *testing.T) {
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
			d := document{Node: Node{Hostname: "tailgate", Port: 443, Tags: tc.tags}}
			if _, err := d.parse(); (err != nil) != tc.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestParseUpstreamURL covers the addresses an HTTP upstream can and cannot be
// reached at. An address no request could be built from has to fail the load,
// since a reload that accepted it would refuse to build the router it just
// promised.
func TestParseUpstreamURL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		url     string
		wantErr bool
	}{
		{name: "http", url: "http://127.0.0.1:9000/mcp"},
		{name: "https", url: "https://mcp.example.com/mcp"},
		{name: "missing", url: "", wantErr: true},
		{name: "relative", url: "/mcp", wantErr: true},
		{name: "no host", url: "http:///mcp", wantErr: true},
		{name: "a scheme no request goes out over", url: "ws://127.0.0.1:9000/mcp", wantErr: true},
		{name: "unparseable", url: "http://[::1", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{{Name: "docs", Transport: TransportHTTP, URL: tc.url}},
			}
			cfg, err := d.parse()
			if (err != nil) != tc.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && cfg.Upstreams[0].URL.String() != tc.url {
				t.Errorf("expected url %s, got %s", tc.url, cfg.Upstreams[0].URL)
			}
		})
	}
}

func TestParseUpstreamTransport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream upstream
		wantErr  bool
	}{
		{
			name:     "unknown transport",
			upstream: upstream{Name: "docs", Transport: "grpc"},
			wantErr:  true,
		},
		{
			name:     "no transport",
			upstream: upstream{Name: "docs"},
			wantErr:  true,
		},
		{
			name:     "stdio without a command",
			upstream: upstream{Name: "files", Transport: TransportStdio},
			wantErr:  true,
		},
		{
			name:     "stdio with a command",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{tc.upstream},
			}
			if _, err := d.parse(); (err != nil) != tc.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestParseIdleTimeout(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		expected time.Duration
		wantErr  bool
	}{
		{name: "unset leaves the transport its own default", raw: ""},
		{name: "minutes", raw: "5m", expected: 5 * time.Minute},
		{name: "seconds", raw: "90s", expected: 90 * time.Second},
		{name: "not a duration", raw: "forever", wantErr: true},
		{name: "a bare number names no unit", raw: "90", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{{Name: "files", Transport: TransportStdio, Command: "mcp-files", IdleTimeout: tc.raw}},
			}
			cfg, err := d.parse()
			if (err != nil) != tc.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && cfg.Upstreams[0].IdleTimeout != tc.expected {
				t.Errorf("expected idle timeout %s, got %s", tc.expected, cfg.Upstreams[0].IdleTimeout)
			}
		})
	}
}

// TestParseStdioCredential covers the uid a stdio child runs under. The file
// spells an unset credential as no uid and no gid, so a half-set pair has to be
// refused: a child keeping tailgate's uid contains nothing, and one whose gid
// falls through to zero runs in the root group.
func TestParseStdioCredential(t *testing.T) {
	for _, tc := range []struct {
		name     string
		upstream upstream
		expected *Credential
		wantErr  bool
	}{
		{
			name:     "stdio without a credential",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files"},
		},
		{
			name:     "stdio with a uid and gid",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570, GID: 570},
			expected: &Credential{UID: 570, GID: 570},
		},
		{
			name:     "stdio uid without a gid",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio gid without a uid",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", GID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio negative uid",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: -1, GID: 570},
			wantErr:  true,
		},
		{
			name:     "stdio negative gid",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: 570, GID: -1},
			wantErr:  true,
		},
		{
			name:     "stdio uid past a uid_t",
			upstream: upstream{Name: "files", Transport: TransportStdio, Command: "mcp-files", UID: math.MaxUint32 + 1, GID: 570},
			wantErr:  true,
		},
		{
			name:     "http upstream with a uid",
			upstream: upstream{Name: "files", Transport: TransportHTTP, URL: "http://127.0.0.1:9000/mcp", UID: 570, GID: 570},
			wantErr:  true,
		},
		{
			name:     "http upstream without one",
			upstream: upstream{Name: "files", Transport: TransportHTTP, URL: "http://127.0.0.1:9000/mcp"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := document{
				Node:      Node{Hostname: "tailgate", Port: 443},
				Upstreams: []upstream{tc.upstream},
			}
			cfg, err := d.parse()
			if (err != nil) != tc.wantErr {
				t.Fatalf("parse error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tc.expected, cfg.Upstreams[0].Credential); diff != "" {
				t.Errorf("credential mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFunnelPort(t *testing.T) {
	for _, tc := range []struct {
		name    string
		port    int
		wantErr bool
	}{
		{name: "https", port: 443},
		{name: "the alternate https port", port: 8443},
		{name: "the high port", port: 10000},
		{name: "unset", port: 0, wantErr: true},
		{name: "http", port: 80, wantErr: true},
		{name: "a port Funnel does not relay", port: 8080, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := FunnelPort(tc.port); (err != nil) != tc.wantErr {
				t.Fatalf("FunnelPort error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
