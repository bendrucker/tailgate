package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testResource = "https://tailgate.tail1234.ts.net/mcp/github"

// fakeIssuer mimics tsidp's discovery and introspection endpoints: opaque
// tokens looked up in a map, RFC 7662 responses, {"active": false} for
// anything unknown.
func fakeIssuer(t *testing.T, tokens map[string]map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"introspection_endpoint":%q}`, base, base+"/introspect")
	})
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		claims, ok := tokens[r.PostForm.Get("token")]
		if !ok {
			fmt.Fprint(w, `{"active":false}`)
			return
		}
		if err := json.NewEncoder(w).Encode(claims); err != nil {
			t.Errorf("encode introspection response: %v", err)
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestVerify(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fresh := float64(now.Add(5 * time.Minute).Unix())
	stale := float64(now.Add(-time.Minute).Unix())

	for _, tc := range []struct {
		name     string
		token    string
		claims   map[string]any
		expected Identity
		invalid  bool
	}{
		{
			name:  "active token bound to resource",
			token: "good",
			claims: map[string]any{
				"active":   true,
				"exp":      fresh,
				"scope":    "openid email",
				"sub":      "12345",
				"username": "bendrucker@github",
				"email":    "bvdrucker@gmail.com",
				"aud":      []any{"client-id", testResource},
			},
			expected: Identity{Subject: "12345", Email: "bvdrucker@gmail.com"},
		},
		{
			name:  "aud as bare string",
			token: "good",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"scope":  "openid email",
				"sub":    "12345",
				"aud":    testResource,
			},
			expected: Identity{Subject: "12345"},
		},
		{
			name:    "unknown token inactive",
			token:   "forged",
			claims:  nil,
			invalid: true,
		},
		{
			name:    "empty token",
			token:   "",
			claims:  nil,
			invalid: true,
		},
		{
			name:  "inactive token",
			token: "revoked",
			claims: map[string]any{
				"active": false,
			},
			invalid: true,
		},
		{
			name:  "active without exp",
			token: "no-exp",
			claims: map[string]any{
				"active": true,
				"sub":    "12345",
				"aud":    testResource,
			},
			invalid: true,
		},
		{
			name:  "expired token",
			token: "expired",
			claims: map[string]any{
				"active": true,
				"exp":    stale,
				"sub":    "12345",
				"aud":    testResource,
			},
			invalid: true,
		},
		{
			name:  "not yet valid",
			token: "future",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"nbf":    fresh,
				"sub":    "12345",
				"aud":    testResource,
			},
			invalid: true,
		},
		{
			name:  "audience for a different upstream",
			token: "wrong-aud",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"sub":    "12345",
				"aud":    []any{"client-id", "https://tailgate.tail1234.ts.net/mcp/linear"},
			},
			invalid: true,
		},
		{
			name:  "audience differs by trailing slash",
			token: "slash-aud",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"sub":    "12345",
				"aud":    testResource + "/",
			},
			invalid: true,
		},
		{
			name:  "audience differs by case",
			token: "case-aud",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"sub":    "12345",
				"aud":    "https://TAILGATE.tail1234.ts.net/mcp/github",
			},
			invalid: true,
		},
		{
			name:  "missing audience",
			token: "no-aud",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"sub":    "12345",
			},
			invalid: true,
		},
		{
			name:  "active without sub",
			token: "no-sub",
			claims: map[string]any{
				"active": true,
				"exp":    fresh,
				"scope":  "openid email",
				"aud":    testResource,
			},
			invalid: true,
		},
		{
			name:  "active claim as string not bool",
			token: "stringly",
			claims: map[string]any{
				"active": "true",
				"exp":    fresh,
				"sub":    "12345",
				"aud":    testResource,
			},
			invalid: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokens := map[string]map[string]any{}
			if tc.claims != nil {
				tokens[tc.token] = tc.claims
			}
			issuer := fakeIssuer(t, tokens)
			verifier, err := NewVerifier(context.Background(), issuer.Client(), issuer.URL)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			verifier.now = func() time.Time { return now }

			id, err := verifier.Verify(context.Background(), tc.token, testResource)
			if tc.invalid {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("expected ErrInvalidToken, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if id.Subject != tc.expected.Subject {
				t.Errorf("expected subject %q, got %q", tc.expected.Subject, id.Subject)
			}
			if id.Email != tc.expected.Email {
				t.Errorf("expected email %q, got %q", tc.expected.Email, id.Email)
			}
			if id.Claims == nil {
				t.Error("expected full claim set on identity")
			}
		})
	}
}

// An empty resource is a wiring bug in tailgate, not a bad bearer: the RFC 8707
// audience binding has nothing to compare against. Verify must refuse before
// introspecting rather than reach audienceContains, where the check would then
// rest entirely on no aud entry ever being the empty string.
func TestVerifyWithoutAResourceIsUnavailable(t *testing.T) {
	clock := newTestClock()
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, activeClaims(clock, 5*time.Minute))
	})
	verifier := newTestVerifier(t, issuer, clock)

	_, err := verifier.Verify(t.Context(), "deadbeef", "")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a missing resource must not classify the token as invalid: %v", err)
	}
	if hits := issuer.hits.Load(); hits != 0 {
		t.Errorf("expected 0 introspection round trips, got %d", hits)
	}
}

func TestVerifyIntrospectionUnavailable(t *testing.T) {
	issuer := fakeIssuer(t, nil)
	verifier, err := NewVerifier(t.Context(), issuer.Client(), issuer.URL)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	issuer.Close()

	_, err = verifier.Verify(t.Context(), "good", testResource)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable when introspection is unreachable, got %v", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatalf("infrastructure failure must not classify the token as invalid: %v", err)
	}
}

func TestNewVerifierTrimsTrailingSlash(t *testing.T) {
	issuer := fakeIssuer(t, nil)
	if _, err := NewVerifier(t.Context(), issuer.Client(), issuer.URL+"/"); err != nil {
		t.Fatalf("expected trailing-slash issuer to construct, got %v", err)
	}
}

func TestNewVerifierRejectsForeignIntrospectionEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"introspection_endpoint":"https://attacker.example/introspect"}`, "http://"+r.Host)
	}))
	t.Cleanup(srv.Close)
	if _, err := NewVerifier(t.Context(), srv.Client(), srv.URL); err == nil {
		t.Fatal("expected construction to fail for an off-origin introspection endpoint")
	}
}

func TestNewVerifierFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "discovery not found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
		{
			name: "no introspection endpoint",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"issuer":"whatever"}`)
			},
		},
		{
			name: "issuer mismatch",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"issuer":"https://evil.example.com","introspection_endpoint":"https://evil.example.com/introspect"}`)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			t.Cleanup(srv.Close)
			if _, err := NewVerifier(context.Background(), srv.Client(), srv.URL); err == nil {
				t.Fatal("expected construction to fail")
			}
		})
	}
}

// TestNewVerifierRejectsIntrospectionEndpointWithUserinfo defends against a
// discovery document whose endpoint carries credentials: net/http would turn
// them into an Authorization header on every introspection, and the refusal
// must not quote them.
func TestNewVerifierRejectsIntrospectionEndpointWithUserinfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"introspection_endpoint":%q}`,
			"http://"+r.Host, "http://attacker:hunter2@"+r.Host+"/introspect")
	}))
	t.Cleanup(srv.Close)

	_, err := NewVerifier(t.Context(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected construction to fail for an introspection endpoint carrying userinfo")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error names the credential: %v", err)
	}
}

// Requiring the email scope restricts no client tsidp would otherwise admit:
// any registered client can ask for it and be granted it. What the check buys
// is that a client which omitted it learns so from a refusal naming the scope,
// rather than from an opaque policy denial once introspection returns no email
// for the allowlist to match.
func TestVerifyRequiresScope(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fresh := float64(now.Add(5 * time.Minute).Unix())

	for _, tc := range []struct {
		name       string
		scopeClaim any
		sufficient bool
	}{
		{name: "required scope alone", scopeClaim: "email", sufficient: true},
		{name: "required scope among several", scopeClaim: "openid profile email", sufficient: true},
		{name: "runs of whitespace between scopes", scopeClaim: "  openid \t email  ", sufficient: true},
		{name: "other scopes without the required one", scopeClaim: "openid profile", sufficient: false},
		{name: "empty scope string", scopeClaim: "", sufficient: false},
		{name: "whitespace only scope string", scopeClaim: "   ", sufficient: false},
		{name: "scope claim absent", scopeClaim: nil, sufficient: false},
		{name: "scope claim as an array", scopeClaim: []any{"openid", "email"}, sufficient: false},
		{name: "scope claim as a number", scopeClaim: float64(1), sufficient: false},
		{name: "scope substring of a granted scope", scopeClaim: "emailx openid", sufficient: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{
				"active": true,
				"exp":    fresh,
				"sub":    "12345",
				"email":  "bvdrucker@gmail.com",
				"aud":    testResource,
			}
			if tc.scopeClaim != nil {
				claims["scope"] = tc.scopeClaim
			}
			issuer := fakeIssuer(t, map[string]map[string]any{"good": claims})
			verifier, err := NewVerifier(context.Background(), issuer.Client(), issuer.URL)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			verifier.now = func() time.Time { return now }
			// The shipped set is empty, so the check is exercised against a
			// requirement the test states rather than one the package default
			// happens to hold.
			verifier.requiredScopes = []string{"email"}

			_, err = verifier.Verify(context.Background(), "good", testResource)
			if tc.sufficient {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInsufficientScope) {
				t.Fatalf("expected ErrInsufficientScope, got %v", err)
			}
			// A good credential missing a scope is a 403, so it must not be
			// classified as a bearer to challenge or as an outage to retry.
			if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrUnavailable) {
				t.Errorf("insufficient scope must not also be invalid or unavailable: %v", err)
			}
		})
	}
}
