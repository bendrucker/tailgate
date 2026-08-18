package authserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	origin = "https://tailgate.example.ts.net"
	issuer = "https://idp.example.ts.net"
)

func testFacade(t *testing.T, client *http.Client) *Facade {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	f, err := New(origin, issuer, client, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return f
}

// The document is the whole point of the package: a client that reads it must
// be sent to tailgate's origin, because a client that ignores it goes there
// anyway. Endpoints naming the issuer would split those two clients apart.
func TestMetadataKeepsEveryEndpointOnTailgatesOrigin(t *testing.T) {
	rec := httptest.NewRecorder()
	testFacade(t, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, MetadataPath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var doc metadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, tc := range []struct{ field, got, want string }{
		{"issuer", doc.Issuer, origin},
		{"authorization_endpoint", doc.AuthorizationEndpoint, origin + AuthorizePath},
		{"token_endpoint", doc.TokenEndpoint, origin + TokenPath},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if !doc.ResourceIndicatorsSupported {
		t.Error("resource_indicators_supported = false; tailgate's audience check requires the client to send resource")
	}
}

func TestHandles(t *testing.T) {
	f := testFacade(t, nil)
	for _, tc := range []struct {
		path string
		want bool
	}{
		{MetadataPath, true},
		{OpenIDMetadataPath, true},
		{AuthorizePath, true},
		{TokenPath, true},
		// RFC 8414 section 3.1 path-suffixed form, which is what a client
		// probes when it treats the MCP path as the issuer.
		{MetadataPath + "/mcp/things", true},
		// The resource server's own discovery subtree stays with the RFC 9728
		// handler.
		{"/.well-known/oauth-protected-resource/mcp/things", false},
		{"/mcp/things", false},
		// Registration is deliberately not fronted. Proxying it would make the
		// call arrive as tailgate's node identity and require allow_dcr in the
		// tailnet policy, coupling tailgate's ability to serve to a rule that
		// matches its node. Nothing else the facade does needs a capability.
		{"/register", false},
		{"/", false},
		{"/authorized", false},
	} {
		if got := f.Handles(tc.path); got != tc.want {
			t.Errorf("Handles(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// Every parameter deciding what is authorized rides the query. Dropping or
// rewriting one changes what the person consents to, so it crosses verbatim.
func TestAuthorizeRedirectsToIssuerPreservingQuery(t *testing.T) {
	query := "response_type=code&client_id=abc123&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback&code_challenge=xyz&code_challenge_method=S256&state=opaque"

	rec := httptest.NewRecorder()
	testFacade(t, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, AuthorizePath+"?"+query, nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got, want := location.Scheme+"://"+location.Host, issuer; got != want {
		t.Errorf("redirect origin = %q, want %q", got, want)
	}
	if location.Path != AuthorizePath {
		t.Errorf("redirect path = %q, want %q", location.Path, AuthorizePath)
	}
	if location.RawQuery != query {
		t.Errorf("query = %q, want it unchanged: %q", location.RawQuery, query)
	}
}

// Client credentials and the resource parameter authenticate the client to the
// issuer and decide the token's audience. Both must survive the hop.
func TestTokenProxiesCredentialsAndResource(t *testing.T) {
	var (
		gotAuthorization string
		gotContentType   string
		gotBody          string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != TokenPath {
			t.Errorf("upstream path = %q, want %q", r.URL.Path, TokenPath)
		}
		gotAuthorization = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"opaque","token_type":"Bearer"}`))
	}))
	defer upstream.Close()

	f, err := New(origin, upstream.URL, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	form := "grant_type=authorization_code&code=abc&resource=https%3A%2F%2Ftailgate.example.ts.net%2Fmcp%2Fthings"
	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic Y2xpZW50OnNlY3JldA==")

	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAuthorization != "Basic Y2xpZW50OnNlY3JldA==" {
		t.Errorf("Authorization = %q, want it forwarded unchanged", gotAuthorization)
	}
	if gotContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want it forwarded unchanged", gotContentType)
	}
	if gotBody != form {
		t.Errorf("body = %q, want %q", gotBody, form)
	}
	if !strings.Contains(rec.Body.String(), `"access_token":"opaque"`) {
		t.Errorf("body = %q, want the issuer's response", rec.Body.String())
	}
}

// An OAuth error carries its detail in the body and its meaning in the status.
// A client can only act on what the issuer said, so both cross unchanged.
func TestTokenPreservesIssuerError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_request","error_description":"invalid resource"}`))
	}))
	defer upstream.Close()

	f, err := New(origin, upstream.URL, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid resource") {
		t.Errorf("body = %q, want the issuer's error detail", rec.Body.String())
	}
}

func TestMethodsRefused(t *testing.T) {
	f := testFacade(t, nil)
	for _, tc := range []struct {
		name, method, path, allow string
	}{
		{"metadata POST", http.MethodPost, MetadataPath, "GET, HEAD"},
		{"authorize POST", http.MethodPost, AuthorizePath, "GET, HEAD"},
		{"token GET", http.MethodGet, TokenPath, "POST"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("status = %d, want 405", rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}
		})
	}
}

// The bound is what keeps an unauthenticated caller from spending tailgate's
// memory on a path that reaches the issuer.
func TestTokenRejectsOversizedRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("oversized request reached the issuer")
	}))
	defer upstream.Close()

	f, err := New(origin, upstream.URL, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(strings.Repeat("a", maxTokenRequestBytes+1)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestNewRejectsUnusableInputs(t *testing.T) {
	for _, tc := range []struct{ name, origin, issuer string }{
		{"empty origin", "", issuer},
		{"empty issuer", origin, ""},
		{"origin without scheme", "tailgate.example.ts.net", issuer},
		{"issuer without scheme", origin, "idp.example.ts.net"},
		{"issuer with query", origin, issuer + "?a=b"},
		{"issuer with fragment", origin, issuer + "#f"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.origin, tc.issuer, http.DefaultClient, slog.New(slog.DiscardHandler)); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}
