package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
