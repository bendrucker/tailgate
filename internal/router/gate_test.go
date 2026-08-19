package router

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
)

func TestMissingCredentialGetsBareChallenge(t *testing.T) {
	h := newHarness(t)

	resp := h.serve(post("/mcp/"+httpUpstream, ""))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	want := `Bearer resource_metadata="https://` + testFQDN + `/.well-known/oauth-protected-resource/mcp/` + httpUpstream + `", scope="openid email"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if h.httpUp.count() != 0 {
		t.Error("unauthenticated request reached the transport")
	}
	if got := h.verifier.audiences(); len(got) != 0 {
		t.Errorf("verifier was called with %v, want no call for a missing credential", got)
	}
	wantAudit := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Upstream: httpUpstream,
		Reason:   ReasonNoToken,
	}}
	if diff := cmp.Diff(wantAudit, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestAuthorizationHeaderParsing(t *testing.T) {
	bearer := `Bearer resource_metadata="https://` + testFQDN + `/.well-known/oauth-protected-resource/mcp/` + httpUpstream + `", scope="openid email"`

	for _, tc := range []struct {
		name      string
		headers   []string
		status    int
		challenge string
	}{
		{
			name:    "lowercase bearer scheme",
			headers: []string{"bearer good"},
			status:  http.StatusOK,
		},
		{
			name:      "basic scheme",
			headers:   []string{"Basic dXNlcjpwYXNz"},
			status:    http.StatusUnauthorized,
			challenge: bearer + `, error="invalid_request"`,
		},
		{
			name:      "scheme without a credential",
			headers:   []string{"Bearer"},
			status:    http.StatusUnauthorized,
			challenge: bearer + `, error="invalid_request"`,
		},
		{
			name:      "blank credential",
			headers:   []string{"Bearer    "},
			status:    http.StatusUnauthorized,
			challenge: bearer + `, error="invalid_request"`,
		},
		{
			name:      "repeated authorization headers",
			headers:   []string{"Bearer good", "Bearer other"},
			status:    http.StatusUnauthorized,
			challenge: bearer + `, error="invalid_request"`,
		},
		{
			name:      "unknown token",
			headers:   []string{"Bearer nope"},
			status:    http.StatusUnauthorized,
			challenge: bearer + `, error="invalid_token"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream)

			req := post("/mcp/"+httpUpstream, "")
			for _, value := range tc.headers {
				req.Header.Add("Authorization", value)
			}
			resp := h.serve(req)
			if resp.StatusCode != tc.status {
				t.Fatalf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != tc.challenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.challenge)
			}
			if tc.status != http.StatusOK && h.httpUp.count() != 0 {
				t.Error("refused request reached the transport")
			}
		})
	}
}

func TestInvalidTokenIsAudited(t *testing.T) {
	h := newHarness(t)

	if resp := h.serve(post("/mcp/"+httpUpstream, "forged")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	want := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Upstream: httpUpstream,
		Reason:   ReasonInvalidToken,
	}}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestVerifierOutageIsUnavailableWithoutChallenge(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "issuer unreachable", err: auth.ErrUnavailable},
		{name: "wrapped unavailable", err: fmt.Errorf("%w: introspection load shed", auth.ErrUnavailable)},
		{name: "unclassified verifier failure", err: errors.New("boom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream)
			h.verifier.err = tc.err

			resp := h.serve(post("/mcp/"+httpUpstream, "good"))
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want 503", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q, want none: an outage must not ask the client to re-authenticate", got)
			}
			if h.httpUp.count() != 0 {
				t.Error("request reached the transport while verification was unavailable")
			}
			want := []auditRecord{{
				Level:    slog.LevelWarn.String(),
				Outcome:  audit.OutcomeDeny,
				Upstream: httpUpstream,
				Reason:   ReasonVerifierUnavailable,
			}}
			if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
				t.Errorf("audit mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

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

// TestOriginGateRefusesDiscoveryBeforeItIsServed pins why tailgate's discovery
// documents carry no CORS headers. The origin gate runs ahead of every
// dispatch and exempts nothing, so a cross-origin browser fetch, the only
// request such a header could act on, never reaches the handler that would
// set one.
func TestOriginGateRefusesDiscoveryBeforeItIsServed(t *testing.T) {
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

// RFC 6750 section 3.1 answers a scope failure with 403: the credential is
// good, so challenging the client to re-authenticate under the same grant
// would only produce the same token. The challenge still rides along, because
// a client reading only the status learns nothing about what to request.
func TestInsufficientScopeIsForbiddenWithAChallenge(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)
	h.verifier.err = fmt.Errorf("%w: token was not granted email", auth.ErrInsufficientScope)

	resp := h.serve(post("/mcp/"+httpUpstream, "good"))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	want := `Bearer resource_metadata="https://` + testFQDN + `/.well-known/oauth-protected-resource/mcp/` + httpUpstream +
		`", scope="openid email", error="insufficient_scope"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if h.httpUp.count() != 0 {
		t.Error("an insufficiently scoped request reached the transport")
	}
	wantAudit := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Upstream: httpUpstream,
		Reason:   ReasonInsufficientScope,
	}}
	if diff := cmp.Diff(wantAudit, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}
