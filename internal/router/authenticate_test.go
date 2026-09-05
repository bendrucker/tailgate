package router

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
		{name: "wrapped unavailable", err: fmt.Errorf("%w: token store unavailable", auth.ErrUnavailable)},
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
