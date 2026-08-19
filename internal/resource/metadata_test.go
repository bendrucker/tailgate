package resource

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func testHandler(t *testing.T) (*URLs, *Handler) {
	t.Helper()
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	handler, err := NewHandler(urls, "https://idp.tail1234.ts.net", []string{"github", "linear"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return urls, handler
}

func TestHandlerServesMetadata(t *testing.T) {
	_, handler := testHandler(t)

	for _, tc := range []struct {
		name     string
		path     string
		expected Metadata
	}{
		{
			name: "github",
			path: "/.well-known/oauth-protected-resource/mcp/github",
			expected: Metadata{
				Resource:               "https://tailgate.tail1234.ts.net/mcp/github",
				AuthorizationServers:   []string{"https://idp.tail1234.ts.net"},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported:        []string{"openid", "email"},
			},
		},
		{
			name: "linear",
			path: "/.well-known/oauth-protected-resource/mcp/linear",
			expected: Metadata{
				Resource:               "https://tailgate.tail1234.ts.net/mcp/linear",
				AuthorizationServers:   []string{"https://idp.tail1234.ts.net"},
				BearerMethodsSupported: []string{"header"},
				ScopesSupported:        []string{"openid", "email"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			if rec.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("expected application/json, got %q", got)
			}
			var got Metadata
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode body %q: %v", rec.Body.String(), err)
			}
			if diff := cmp.Diff(tc.expected, got); diff != "" {
				t.Errorf("metadata mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandlerServesOnlyDocumentFields(t *testing.T) {
	_, handler := testHandler(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp/github", nil))

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	expected := map[string]any{
		"resource":                 "https://tailgate.tail1234.ts.net/mcp/github",
		"authorization_servers":    []any{"https://idp.tail1234.ts.net"},
		"bearer_methods_supported": []any{"header"},
		"scopes_supported":         []any{"openid", "email"},
	}
	if diff := cmp.Diff(expected, got); diff != "" {
		t.Errorf("document mismatch (-want +got):\n%s", diff)
	}
}

func TestHandlerRejects(t *testing.T) {
	_, handler := testHandler(t)

	for _, tc := range []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		{
			name:     "unknown upstream",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/nope",
			expected: http.StatusNotFound,
		},
		{
			name:     "empty upstream",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/",
			expected: http.StatusNotFound,
		},
		{
			name:     "no mcp segment",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource",
			expected: http.StatusNotFound,
		},
		{
			name:     "dot dot traversal",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/nope/../github",
			expected: http.StatusNotFound,
		},
		{
			name:     "encoded traversal",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/%2e%2e/mcp/github",
			expected: http.StatusNotFound,
		},
		{
			name:     "encoded upstream name",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/%67ithub",
			expected: http.StatusNotFound,
		},
		{
			name:     "double slash",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp//github",
			expected: http.StatusNotFound,
		},
		{
			name:     "trailing segment",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/github/extra",
			expected: http.StatusNotFound,
		},
		{
			name:     "trailing slash",
			method:   http.MethodGet,
			path:     "/.well-known/oauth-protected-resource/mcp/github/",
			expected: http.StatusNotFound,
		},
		{
			name:     "upstream path",
			method:   http.MethodGet,
			path:     "/mcp/github",
			expected: http.StatusNotFound,
		},
		{
			name:     "post",
			method:   http.MethodPost,
			path:     "/.well-known/oauth-protected-resource/mcp/github",
			expected: http.StatusMethodNotAllowed,
		},
		{
			name:     "delete",
			method:   http.MethodDelete,
			path:     "/.well-known/oauth-protected-resource/mcp/github",
			expected: http.StatusMethodNotAllowed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, rec.Code)
			}
			if tc.expected == http.StatusMethodNotAllowed {
				if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
					t.Errorf("expected Allow GET, HEAD, got %q", got)
				}
			}
		})
	}
}

func TestHandlerHead(t *testing.T) {
	_, handler := testHandler(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/.well-known/oauth-protected-resource/mcp/github", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected application/json, got %q", got)
	}
}

func TestNewHandlerRejects(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}

	for _, tc := range []struct {
		name      string
		issuer    string
		upstreams []string
	}{
		{name: "empty issuer", issuer: "", upstreams: []string{"github"}},
		{name: "relative issuer", issuer: "idp.tail1234.ts.net", upstreams: []string{"github"}},
		{name: "issuer with query", issuer: "https://idp.tail1234.ts.net?x=1", upstreams: []string{"github"}},
		{name: "issuer with fragment", issuer: "https://idp.tail1234.ts.net#x", upstreams: []string{"github"}},
		{name: "empty upstream name", issuer: "https://idp.tail1234.ts.net", upstreams: []string{""}},
		{name: "upstream name with slash", issuer: "https://idp.tail1234.ts.net", upstreams: []string{"a/b"}},
		{name: "upstream name traversal", issuer: "https://idp.tail1234.ts.net", upstreams: []string{".."}},
		{name: "upstream name needing escape", issuer: "https://idp.tail1234.ts.net", upstreams: []string{"a b"}},
		{name: "duplicate upstream", issuer: "https://idp.tail1234.ts.net", upstreams: []string{"github", "github"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHandler(urls, tc.issuer, tc.upstreams); err == nil {
				t.Errorf("expected error for issuer %q upstreams %v", tc.issuer, tc.upstreams)
			}
		})
	}
}

func TestNewHandlerTrimsIssuerSlash(t *testing.T) {
	urls, err := NewURLs("tailgate.tail1234.ts.net", 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	handler, err := NewHandler(urls, "https://idp.tail1234.ts.net/", []string{"github"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp/github", nil))

	var got Metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	if diff := cmp.Diff([]string{"https://idp.tail1234.ts.net"}, got.AuthorizationServers); diff != "" {
		t.Errorf("authorization_servers mismatch (-want +got):\n%s", diff)
	}
}

// TestDiscoveryFollowsChallenge walks the path a real MCP client takes: it
// reads resource_metadata out of the challenge tailgate would return on a 401,
// fetches that URL, and checks the document names the resource it was
// challenged for.
func TestDiscoveryFollowsChallenge(t *testing.T) {
	urls, handler := testHandler(t)
	server := httptest.NewServer(handler)
	defer server.Close()

	challenge := urls.Challenge("github", ChallengeOptions{Error: "invalid_token"})
	metadataURL, ok := challengeParam(challenge, "resource_metadata")
	if !ok {
		t.Fatalf("no resource_metadata in %q", challenge)
	}
	if metadataURL != urls.MetadataURL("github") {
		t.Fatalf("expected %s, got %s", urls.MetadataURL("github"), metadataURL)
	}

	resp, err := server.Client().Get(server.URL + urls.MetadataPath("github"))
	if err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var doc Metadata
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode body %q: %v", body, err)
	}
	if doc.Resource != urls.ResourceURL("github") {
		t.Errorf("expected resource %s, got %s", urls.ResourceURL("github"), doc.Resource)
	}
	if diff := cmp.Diff([]string{"https://idp.tail1234.ts.net"}, doc.AuthorizationServers); diff != "" {
		t.Errorf("authorization_servers mismatch (-want +got):\n%s", diff)
	}
}

// Every required scope must be advertised. Advertising less than is enforced
// refuses a client that requested exactly what the metadata document and the
// challenge told it to request, with nothing in either naming what it missed.
func TestRequiredScopesAreAdvertised(t *testing.T) {
	for _, scope := range RequiredScopes() {
		if !slices.Contains(scopesSupported, scope) {
			t.Errorf("required scope %q is not in scopes_supported %v", scope, scopesSupported)
		}
	}
}

// The shipped set is empty, so what is pinned is that the accessor copies
// rather than aliases. A future entry must not be editable by a caller.
func TestRequiredScopesCopiesRatherThanAliases(t *testing.T) {
	scopesRequired = []string{"email"}
	t.Cleanup(func() { scopesRequired = nil })

	returned := RequiredScopes()
	returned[0] = "mutated"
	if got := RequiredScopes(); got[0] == "mutated" {
		t.Error("a caller edited the required scopes through the returned slice")
	}
}

// Nothing is required today. A change to that is a decision about which clients
// can reach any upstream at all, so it fails here until this test is updated
// alongside it.
func TestNoScopeIsRequired(t *testing.T) {
	if got := RequiredScopes(); len(got) != 0 {
		t.Errorf("RequiredScopes() = %v, want none", got)
	}
}
