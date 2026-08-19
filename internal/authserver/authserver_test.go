package authserver

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	origin = "https://tailgate.example.ts.net"
	issuer = "https://idp.example.ts.net"

	// credentialedForm is the minimum a token request must carry to be
	// forwarded: the facade refuses one that authenticates no client.
	credentialedForm = "grant_type=authorization_code&client_id=abc&client_secret=shh"
)

// testUpstreams is the configured upstream set, which decides the RFC 8414
// section 3.1 metadata paths the facade answers.
var testUpstreams = []string{"things", "github"}

func testFacade(t *testing.T, client *http.Client) *Facade {
	t.Helper()
	if client == nil {
		client = http.DefaultClient
	}
	f, err := New(origin, issuer, testUpstreams, client, slog.New(slog.DiscardHandler))
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

	f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
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

	f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(credentialedForm))
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

	f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
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
			if _, err := New(tc.origin, tc.issuer, testUpstreams, http.DefaultClient, slog.New(slog.DiscardHandler)); err == nil {
				t.Fatal("New succeeded, want an error")
			}
		})
	}
}

// A redirect from the token endpoint would be followed from inside the
// tailnet on behalf of an unauthenticated caller, turning the facade into a
// fetcher for anything the issuer's node can reach.
func TestTokenDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == TokenPath {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.Write([]byte("tailnet-only"))
	}))
	defer upstream.Close()

	f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(credentialedForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", rec.Code)
	}
	if got := requests.Load(); got != 1 {
		t.Errorf("issuer requests = %d, want 1", got)
	}
	if strings.Contains(rec.Body.String(), "tailnet-only") {
		t.Errorf("body = %q, want nothing fetched from the redirect target", rec.Body.String())
	}
}

// The token endpoint is unauthenticated, so an issuer that never answers must
// not be a way to hold tailgate's connections open.
func TestTokenBoundsASlowIssuer(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.timeout = 50 * time.Millisecond

	req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(credentialedForm))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}

// The token endpoint is unauthenticated and reaches tsidp over the tailnet as
// tailgate's own node. A request carrying no client credentials must stop at
// the facade rather than arrive there identified by that node.
func TestTokenRequiresClientCredentials(t *testing.T) {
	for _, tc := range []struct {
		name       string
		header     string
		form       string
		wantIssuer bool
	}{
		{
			name: "no credentials at all",
			form: "grant_type=authorization_code&code=abc",
		},
		{
			name: "client id without a secret",
			form: "grant_type=authorization_code&client_id=abc",
		},
		{
			name: "empty secret",
			form: "grant_type=authorization_code&client_id=abc&client_secret=",
		},
		{
			name:   "bearer token instead of client authentication",
			header: "Bearer opaque",
			form:   "grant_type=authorization_code",
		},
		{
			name:   "basic scheme with no credential",
			header: "Basic ",
			form:   "grant_type=authorization_code",
		},
		{
			name:       "basic authorization header",
			header:     "Basic Y2xpZW50OnNlY3JldA==",
			form:       "grant_type=authorization_code",
			wantIssuer: true,
		},
		{
			name:       "client id and secret in the form",
			form:       credentialedForm,
			wantIssuer: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached.Store(true)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"opaque","token_type":"Bearer"}`))
			}))
			defer upstream.Close()

			f, err := New(origin, upstream.URL, testUpstreams, upstream.Client(), slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(tc.form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, req)

			if got := reached.Load(); got != tc.wantIssuer {
				t.Errorf("issuer reached = %v, want %v", got, tc.wantIssuer)
			}
			if tc.wantIssuer {
				if rec.Code != http.StatusOK {
					t.Errorf("status = %d, want 200", rec.Code)
				}
				return
			}
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
			var oauthErr struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &oauthErr); err != nil {
				t.Fatalf("decode refusal: %v", err)
			}
			if oauthErr.Error != "invalid_client" {
				t.Errorf("error = %q, want invalid_client", oauthErr.Error)
			}
		})
	}
}

// The facade must not answer discovery for a resource that does not exist. A
// client trusting a document it found there would go looking for tokens for an
// upstream tailgate does not serve.
func TestMetadataResolvesOnlyConfiguredUpstreams(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{name: "configured upstream", path: MetadataPath + "/mcp/things", want: true},
		{name: "second configured upstream", path: MetadataPath + "/mcp/github", want: true},
		{name: "unconfigured upstream", path: MetadataPath + "/mcp/absent"},
		{name: "configured name with a suffix", path: MetadataPath + "/mcp/things-staging"},
		{name: "configured name with a trailing slash", path: MetadataPath + "/mcp/things/"},
		{name: "configured name with a further segment", path: MetadataPath + "/mcp/things/extra"},
		{name: "traversal to a configured name", path: MetadataPath + "/mcp/absent/../things"},
		{name: "traversal out of the subtree", path: MetadataPath + "/mcp/../../etc/passwd"},
		{name: "bare subtree slash", path: MetadataPath + "/"},
		{name: "arbitrary suffix", path: MetadataPath + "/anything"},
		{name: "percent encoded configured name", path: MetadataPath + "/mcp/%74hings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := testFacade(t, nil)
			if got := f.Handles(tc.path); got != tc.want {
				t.Errorf("Handles(%q) = %v, want %v", tc.path, got, tc.want)
			}

			rec := httptest.NewRecorder()
			f.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))

			want := http.StatusNotFound
			if tc.want {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Errorf("status = %d, want %d", rec.Code, want)
			}
		})
	}
}

// RFC 8414 section 3.1 says an authorization server's metadata endpoint should
// support CORS. tailgate does not: the router refuses a request carrying a
// foreign Origin before any handler runs, so a header here would grant nothing
// and would describe a request the gate never admits.
func TestMetadataCarriesNoCrossOriginGrant(t *testing.T) {
	for _, path := range []string{MetadataPath, OpenIDMetadataPath} {
		rec := httptest.NewRecorder()
		testFacade(t, nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", path, rec.Code)
		}
		for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Expose-Headers"} {
			if got := rec.Header().Get(header); got != "" {
				t.Errorf("%s %s = %q, want none", path, header, got)
			}
		}
	}
}
