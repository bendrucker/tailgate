package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/authserver"
	"github.com/bendrucker/tailgate/internal/config"
	"github.com/bendrucker/tailgate/internal/resource"
)

const (
	testFQDN     = "tailgate.example.ts.net"
	testPort     = 443
	testIssuer   = "https://idp.example.ts.net"
	testOrigin   = "https://tailgate.example.ts.net"
	testUpstream = "docs"
	testResource = "https://tailgate.example.ts.net/mcp/docs"
	allowedToken = "allowed-token"
	otherToken   = "other-token"
	deniedToken  = "denied-token"
)

// fakeVerifier resolves the tokens the test registers, standing in for the
// issuer the real verifier introspects against.
type fakeVerifier struct {
	mu         sync.Mutex
	identities map[string]auth.Identity
	resources  []string
}

func (v *fakeVerifier) Verify(_ context.Context, token, res string) (auth.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.resources = append(v.resources, res)
	id, ok := v.identities[token]
	if !ok {
		return auth.Identity{}, auth.ErrInvalidToken
	}
	return id, nil
}

func (v *fakeVerifier) audiences() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.resources...)
}

// respondJSON is the upstream behavior every test that only cares about the
// gate in front of it uses.
func respondJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
}

// testHandler assembles the wiring against an upstream answering with respond,
// returning the public handler and the requests that reached that upstream.
func testHandler(t *testing.T, respond http.HandlerFunc) (http.Handler, *fakeVerifier, func() []*http.Request) {
	t.Helper()

	var mu sync.Mutex
	var received []*http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, r.Clone(context.Background()))
		mu.Unlock()
		respond(w, r)
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{
		Node: config.Node{Hostname: "tailgate", Port: testPort},
		OIDC: config.OIDC{Issuer: testIssuer},
		Upstreams: []config.Upstream{
			{Name: testUpstream, Transport: config.TransportHTTP, URL: upstream.URL},
		},
		Policy: []config.Rule{
			{Upstream: testUpstream, Allow: []config.Match{{Email: "you@example.ts.net"}}},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	urls, err := resource.NewURLs(testFQDN, testPort)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}

	verifier := &fakeVerifier{identities: map[string]auth.Identity{
		allowedToken: {Subject: "1", Email: "you@example.ts.net"},
		otherToken:   {Subject: "3", Email: "you@example.ts.net"},
		deniedToken:  {Subject: "2", Email: "someone@example.ts.net"},
	}}

	logger := discardLogger()
	rt, err := handler(cfg, urls, verifier, http.DefaultClient, logger, audit.New(logger))
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(func() { rt.Close() })

	return rt, verifier, func() []*http.Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]*http.Request(nil), received...)
	}
}

func TestHandlerServesMetadata(t *testing.T) {
	rt, _, _ := testHandler(t, respondJSON)

	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp/docs", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var doc resource.Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	if doc.Resource != testResource {
		t.Errorf("expected resource %s, got %s", testResource, doc.Resource)
	}
	// The document names tailgate, not the issuer: clients obtain tokens from the
	// facade, which is the only authorization surface reachable from off-tailnet.
	if diff := cmp.Diff([]string{testOrigin}, doc.AuthorizationServers); diff != "" {
		t.Errorf("authorization servers differ:\n%s", diff)
	}
}

func TestHandlerAuthorizes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		token     string
		origin    string
		expected  int
		challenge bool
		forwarded bool
	}{
		{
			name:      "no token",
			expected:  http.StatusUnauthorized,
			challenge: true,
		},
		{
			name:      "unknown token",
			token:     "not-a-token",
			expected:  http.StatusUnauthorized,
			challenge: true,
		},
		{
			name:     "identity outside policy",
			token:    deniedToken,
			expected: http.StatusForbidden,
		},
		{
			name:     "foreign origin",
			token:    allowedToken,
			origin:   "https://evil.example.com",
			expected: http.StatusForbidden,
		},
		{
			name:      "allowed identity",
			token:     allowedToken,
			expected:  http.StatusOK,
			forwarded: true,
		},
		{
			name:      "allowed identity from the canonical origin",
			token:     allowedToken,
			origin:    testOrigin,
			expected:  http.StatusOK,
			forwarded: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt, _, forwarded := testHandler(t, respondJSON)

			req := httptest.NewRequest(http.MethodPost, "/mcp/docs", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
			req.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			rt.ServeHTTP(rec, req)

			if rec.Code != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, rec.Code)
			}

			challenge := rec.Header().Get("WWW-Authenticate")
			if tc.challenge {
				metadata := "https://tailgate.example.ts.net/.well-known/oauth-protected-resource/mcp/docs"
				if !strings.Contains(challenge, `resource_metadata="`+metadata+`"`) {
					t.Errorf("expected challenge naming %s, got %q", metadata, challenge)
				}
			} else if challenge != "" {
				t.Errorf("expected no challenge, got %q", challenge)
			}

			reached := forwarded()
			if !tc.forwarded {
				if len(reached) != 0 {
					t.Fatalf("expected no request to reach the upstream, got %d", len(reached))
				}
				return
			}
			if len(reached) != 1 {
				t.Fatalf("expected 1 request to reach the upstream, got %d", len(reached))
			}
			if got := reached[0].Header.Get("Authorization"); got != "" {
				t.Errorf("expected the caller's credentials stripped, got %q", got)
			}
		})
	}
}

// TestHandlerVerifiesAgainstCanonicalAudience pins the audience the verifier
// checks to the same string the metadata document advertises. A drift between
// them accepts a token minted for another resource.
func TestHandlerVerifiesAgainstCanonicalAudience(t *testing.T) {
	rt, verifier, _ := testHandler(t, respondJSON)

	req := httptest.NewRequest(http.MethodPost, "/mcp/docs", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+allowedToken)
	rt.ServeHTTP(httptest.NewRecorder(), req)

	if diff := cmp.Diff([]string{testResource}, verifier.audiences()); diff != "" {
		t.Errorf("audiences differ:\n%s", diff)
	}
}

// TestHandlerBindsSessionToIdentity covers the hijack the MCP spec warns about:
// the upstream sees only the session header, so a session another caller
// learned must be refused before it reaches one.
func TestHandlerBindsSessionToIdentity(t *testing.T) {
	const session = "upstream-session"
	rt, _, _ := testHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Mcp-Session-Id", session)
		respondJSON(w, nil)
	})

	initialize := httptest.NewRequest(http.MethodPost, "/mcp/docs", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	initialize.Header.Set("Authorization", "Bearer "+allowedToken)
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, initialize)
	if rec.Code != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Mcp-Session-Id"); got != session {
		t.Fatalf("expected session %s, got %q", session, got)
	}

	for _, tc := range []struct {
		name     string
		token    string
		expected int
	}{
		{
			name:     "the identity that opened it",
			token:    allowedToken,
			expected: http.StatusOK,
		},
		{
			name:     "another authorized identity",
			token:    otherToken,
			expected: http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp/docs", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`))
			req.Header.Set("Authorization", "Bearer "+tc.token)
			req.Header.Set("Mcp-Session-Id", session)
			rec := httptest.NewRecorder()
			rt.ServeHTTP(rec, req)
			if rec.Code != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, rec.Code)
			}
		})
	}
}

// TestHandlerStreamsSSE pins SSE fidelity through the assembled handler. The id
// and retry fields drive a client's resumption, so a proxy that rewrites or
// buffers them breaks reconnection rather than the response.
func TestHandlerStreamsSSE(t *testing.T) {
	const stream = "event: message\nid: 42\nretry: 5000\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"
	rt, _, _ := testHandler(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte(stream))
		w.(http.Flusher).Flush()
	})

	req := httptest.NewRequest(http.MethodPost, "/mcp/docs", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	req.Header.Set("Authorization", "Bearer "+allowedToken)
	req.Header.Set("Accept", "text/event-stream")
	rec := httptest.NewRecorder()
	rt.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Type"); got != "text/event-stream" {
		t.Errorf("expected text/event-stream, got %q", got)
	}
	if got := rec.Body.String(); got != stream {
		t.Errorf("expected stream %q, got %q", stream, got)
	}
}

// The facade's endpoints must resolve on the assembled surface, unauthenticated
// and ahead of upstream routing. A client that skips RFC 9728 discovery reaches
// tailgate with no token and no knowledge of the issuer, so a 404 or a 401 here
// is the failure this package exists to prevent.
func TestHandlerServesAuthorizationServerSurface(t *testing.T) {
	rt, _, _ := testHandler(t, respondJSON)

	t.Run("metadata", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authserver.MetadataPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		var doc struct {
			Issuer                string `json:"issuer"`
			AuthorizationEndpoint string `json:"authorization_endpoint"`
			TokenEndpoint         string `json:"token_endpoint"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("unmarshal metadata: %v", err)
		}
		origin := strings.TrimSuffix(testResource, "/mcp/docs")
		for _, tc := range []struct{ field, got, want string }{
			{"issuer", doc.Issuer, origin},
			{"authorization_endpoint", doc.AuthorizationEndpoint, origin + authserver.AuthorizePath},
			{"token_endpoint", doc.TokenEndpoint, origin + authserver.TokenPath},
		} {
			if tc.got != tc.want {
				t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
			}
		}
	})

	t.Run("authorize redirects to the issuer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, authserver.AuthorizePath+"?client_id=abc&state=xyz", nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("expected 302, got %d", rec.Code)
		}
		want := testIssuer + authserver.AuthorizePath + "?client_id=abc&state=xyz"
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("Location = %q, want %q", got, want)
		}
	})
}
