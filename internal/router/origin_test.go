package router

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bendrucker/tailgate/internal/audit"
)

func TestNormalizeOrigin(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		want   string
	}{
		{name: "canonical https origin", origin: "https://host.example", want: "https://host.example"},
		{name: "default https port", origin: "https://host.example:443", want: "https://host.example"},
		{name: "default http port", origin: "http://host.example:80", want: "http://host.example"},
		{name: "explicit non default port", origin: "https://host.example:8443", want: "https://host.example:8443"},
		{name: "mixed case", origin: "HTTPS://Host.Example", want: "https://host.example"},
		{name: "surrounding space", origin: "  https://host.example  ", want: "https://host.example"},
		{name: "null origin", origin: "null", want: ""},
		{name: "empty origin", origin: "", want: ""},
		{name: "no host", origin: "https://", want: ""},
		{name: "file scheme", origin: "file:///etc/passwd", want: ""},
		{name: "with path", origin: "https://host.example/mcp", want: ""},
		{name: "with query", origin: "https://host.example?a=b", want: ""},
		{name: "ipv6 literal", origin: "http://[::1]", want: "http://[::1]"},
		{name: "ipv6 literal with port", origin: "http://[::1]:8080", want: "http://[::1]:8080"},
		{name: "ipv6 literal on the default port", origin: "https://[2001:db8::1]:443", want: "https://[2001:db8::1]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeOrigin(tc.origin); got != tc.want {
				t.Errorf("normalizeOrigin(%q) = %q, want %q", tc.origin, got, tc.want)
			}
		})
	}
}

// TestRepeatedOriginIsRefused defends the header-agreement invariant at the
// Origin header. tailgate forwards it, so deciding on the first of several
// would let an upstream that reads the last execute against an origin tailgate
// never checked.
func TestRepeatedOriginIsRefused(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)

	req := post("/mcp/"+httpUpstream, "good")
	req.Header.Add("Origin", testOrigin)
	req.Header.Add("Origin", "https://evil.example.com")

	resp := h.serve(req)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if h.httpUp.count() != 0 {
		t.Error("request with repeated origins reached the transport")
	}
	wantAudit := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Upstream: httpUpstream,
		Reason:   ReasonOriginNotAllowed,
	}}
	if diff := cmp.Diff(wantAudit, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

// recordingAuthServer reports whether the facade was reached.
type recordingAuthServer struct {
	paths  map[string]bool
	served atomic.Int64
}

func (a *recordingAuthServer) Handles(path string) bool { return a.paths[path] }

func (a *recordingAuthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.served.Add(1)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"issuer":"https://tailgate.example"}`))
}

// TestOriginRefusesDiscoveryBeforeItIsServed pins why tailgate's discovery
// documents carry no CORS headers. The origin gate runs ahead of every
// dispatch and exempts nothing, so a cross-origin browser fetch, the only
// request such a header could act on, never reaches the handler that would
// set one.
func TestOriginRefusesDiscoveryBeforeItIsServed(t *testing.T) {
	facade := &recordingAuthServer{paths: map[string]bool{
		"/.well-known/oauth-authorization-server": true,
		"/.well-known/openid-configuration":       true,
	}}
	h := newHarness(t, func(o *Options) { o.AuthServer = facade })

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "authorization server metadata", path: "/.well-known/oauth-authorization-server"},
		{name: "openid configuration", path: "/.well-known/openid-configuration"},
		{name: "protected resource metadata", path: h.urls.MetadataPath(httpUpstream)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Origin", "https://evil.example.com")

			resp := h.serve(req)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
		})
	}

	if got := facade.served.Load(); got != 0 {
		t.Errorf("facade served %d cross-origin requests, want 0", got)
	}
}
