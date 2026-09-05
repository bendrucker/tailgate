package authserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/cimd"
	"github.com/bendrucker/tailgate/internal/resource"
)

const (
	testFQDN     = "tailgate.example.ts.net"
	origin       = "https://tailgate.example.ts.net"
	testUpstream = "docs"
	testResource = origin + "/mcp/docs"
	callback     = "https://client.example.com/callback"
	loopbackCB   = "http://127.0.0.1/cb"
	verifier     = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

var (
	peer      = netip.MustParseAddrPort("100.101.102.103:52000")
	challenge = s256(verifier)
)

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fakeIdentify stands in for the node's WhoIs, answering with whatever the
// test set and counting calls.
type fakeIdentify struct {
	mu    sync.Mutex
	calls int
	who   *apitype.WhoIsResponse
	err   error
}

func (f *fakeIdentify) identify(_ context.Context, _ netip.AddrPort) (*apitype.WhoIsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.who, f.err
}

func (f *fakeIdentify) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func person() *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "laptop.example.ts.net."},
		UserProfile: &tailcfg.UserProfile{ID: 12345, LoginName: "you@example.com", DisplayName: "You"},
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fixture struct {
	server   *Server
	tokens   *auth.Tokens
	identify *fakeIdentify
	clock    *testClock
	clientID string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}

	var clientOrigin *httptest.Server
	clientOrigin = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"client_id":     clientOrigin.URL + r.URL.Path,
			"client_name":   "Claude",
			"client_uri":    "https://client.example.com",
			"redirect_uris": []string{callback, loopbackCB},
		})
	}))
	t.Cleanup(clientOrigin.Close)

	urls, err := resource.NewURLs(testFQDN, 443)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	tokens := auth.NewTokens(auth.WithClock(clock.Now))
	identify := &fakeIdentify{who: person()}
	server, err := New(Options{
		Resources:   urls,
		HasUpstream: func(name string) bool { return name == testUpstream || name == "other" },
		Tokens:      tokens,
		Identify:    identify.identify,
		Clients:     cimd.NewFetcher(clientOrigin.Client(), cimd.WithClock(clock.Now)),
		Logger:      slog.New(slog.DiscardHandler),
		Clock:       clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{
		server:   server,
		tokens:   tokens,
		identify: identify,
		clock:    clock,
		clientID: clientOrigin.URL + "/oauth/client",
	}
}

// authorizeQuery is a complete, valid authorization request.
func (f *fixture) authorizeQuery() url.Values {
	return url.Values{
		"client_id":             {f.clientID},
		"redirect_uri":          {callback},
		"response_type":         {"code"},
		"state":                 {"xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"openid email"},
		"resource":              {testResource},
	}
}

func onTailnet(r *http.Request) *http.Request {
	return r.WithContext(auth.WithPeerAddr(r.Context(), peer))
}

func (f *fixture) get(path string, query url.Values, tailnet bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	if tailnet {
		req = onTailnet(req)
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) post(path string, form url.Values, tailnet bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tailnet {
		req = onTailnet(req)
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)
	return rec
}

var requestField = regexp.MustCompile(`name="request" value="([^"]+)"`)

func (f *fixture) consent(t *testing.T, query url.Values) string {
	t.Helper()
	rec := f.get(AuthorizePath, query, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /authorize = %d: %s", rec.Code, rec.Body.String())
	}
	match := requestField.FindStringSubmatch(rec.Body.String())
	if match == nil {
		t.Fatalf("consent page carries no request field:\n%s", rec.Body.String())
	}
	return match[1]
}

// approve answers the consent page and returns the code the redirect carries.
func (f *fixture) approve(t *testing.T, request string) string {
	t.Helper()
	rec := f.post(AuthorizePath, url.Values{"request": {request}, "decision": {"approve"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /authorize = %d: %s", rec.Code, rec.Body.String())
	}
	location := redirectQuery(t, rec, callback)
	if location.Get("error") != "" {
		t.Fatalf("approval redirected with error %q: %s", location.Get("error"), location.Get("error_description"))
	}
	return location.Get("code")
}

func (f *fixture) authorize(t *testing.T) string {
	t.Helper()
	return f.approve(t, f.consent(t, f.authorizeQuery()))
}

func (f *fixture) codeForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {f.clientID},
		"code":          {code},
		"redirect_uri":  {callback},
		"code_verifier": {verifier},
	}
}

type tokenBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func (f *fixture) redeem(t *testing.T, form url.Values) tokenBody {
	t.Helper()
	rec := f.post(TokenPath, form, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /token = %d: %s", rec.Code, rec.Body.String())
	}
	for header, want := range map[string]string{"Cache-Control": "no-store", "Pragma": "no-cache", "Content-Type": "application/json"} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	var body tokenBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	return body
}

// redirectQuery checks the redirect went to redirectURI and returns its query.
func redirectQuery(t *testing.T, rec *httptest.ResponseRecorder, redirectURI string) url.Values {
	t.Helper()
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	base := *location
	base.RawQuery = ""
	if base.String() != redirectURI {
		t.Fatalf("redirected to %s, want %s", base.String(), redirectURI)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	return location.Query()
}

func oauthError(t *testing.T, rec *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response %q: %v", rec.Body.String(), err)
	}
	return body.Error, body.Description
}

func TestAuthorizationCodeFlow(t *testing.T) {
	f := newFixture(t)

	rec := f.get(AuthorizePath, f.authorizeQuery(), true)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /authorize = %d: %s", rec.Code, rec.Body.String())
	}
	page := rec.Body.String()
	for _, want := range []string{"Claude", "127.0.0.1", "client.example.com", testUpstream, testResource, "openid", "email", "you@example.com", "You"} {
		if !strings.Contains(page, want) {
			t.Errorf("consent page does not show %q", want)
		}
	}
	for header, want := range map[string]string{
		"Content-Type":            "text/html; charset=utf-8",
		"Cache-Control":           "no-store",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	request := requestField.FindStringSubmatch(page)
	if request == nil {
		t.Fatal("consent page carries no request field")
	}

	rec = f.post(AuthorizePath, url.Values{"request": {request[1]}, "decision": {"approve"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /authorize = %d: %s", rec.Code, rec.Body.String())
	}
	location := redirectQuery(t, rec, callback)
	if got := location.Get("state"); got != "xyz" {
		t.Errorf("state = %q, want xyz", got)
	}
	code := location.Get("code")
	if code == "" {
		t.Fatal("redirect carries no code")
	}
	if got := f.identify.count(); got != 2 {
		t.Errorf("identify called %d times, want once per request", got)
	}

	issued := f.redeem(t, f.codeForm(code))
	if issued.TokenType != "Bearer" || issued.ExpiresIn != int64(auth.DefaultAccessTokenTTL.Seconds()) || issued.Scope != "openid email" {
		t.Errorf("token response = %+v", issued)
	}

	id, err := f.tokens.Verify(t.Context(), issued.AccessToken, testResource)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := auth.Identity{
		Subject: "12345",
		Email:   "you@example.com",
		Claims: map[string]any{
			"sub":       "12345",
			"email":     "you@example.com",
			"name":      "You",
			"node":      "laptop.example.ts.net.",
			"scope":     "openid email",
			"client_id": f.clientID,
			"aud":       testResource,
			"iat":       f.clock.Now().Unix(),
			"exp":       f.clock.Now().Add(auth.DefaultAccessTokenTTL).Unix(),
		},
	}
	if diff := cmp.Diff(want, id); diff != "" {
		t.Errorf("identity mismatch (-want +got):\n%s", diff)
	}
	if _, err := f.tokens.Verify(t.Context(), issued.AccessToken, origin+"/mcp/other"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("token verified for another upstream: %v", err)
	}

	refreshed := f.redeem(t, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {issued.RefreshToken},
	})
	if _, err := f.tokens.Verify(t.Context(), refreshed.AccessToken, testResource); err != nil {
		t.Errorf("refreshed access token does not verify: %v", err)
	}
	rec = f.post(TokenPath, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {issued.RefreshToken},
	}, false)
	if code, _ := oauthError(t, rec); rec.Code != http.StatusBadRequest || code != "invalid_grant" {
		t.Errorf("reusing a refresh token = %d %s, want 400 invalid_grant", rec.Code, code)
	}
}

// A replayed code means it leaked, and the tokens went to whoever redeemed it
// first, so the replay revokes them.
func TestCodeReplayRevokesIssuedTokens(t *testing.T) {
	f := newFixture(t)
	code := f.authorize(t)
	issued := f.redeem(t, f.codeForm(code))

	rec := f.post(TokenPath, f.codeForm(code), false)
	if errCode, _ := oauthError(t, rec); rec.Code != http.StatusBadRequest || errCode != "invalid_grant" {
		t.Fatalf("replay = %d %s, want 400 invalid_grant", rec.Code, errCode)
	}
	if _, err := f.tokens.Verify(t.Context(), issued.AccessToken, testResource); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("access token survived a code replay: %v", err)
	}
	rec = f.post(TokenPath, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {issued.RefreshToken},
	}, false)
	if errCode, _ := oauthError(t, rec); errCode != "invalid_grant" {
		t.Errorf("refresh token survived a code replay: %d %s", rec.Code, errCode)
	}
}

// Identification is impossible over Funnel, so both halves of /authorize
// answer a page telling the person where to go, and never ask WhoIs.
func TestAuthorizeRefusesRequestsWithNoTailnetPeer(t *testing.T) {
	f := newFixture(t)
	request := f.consent(t, f.authorizeQuery())
	calls := f.identify.count()

	for _, tc := range []struct {
		name string
		rec  *httptest.ResponseRecorder
	}{
		{name: "consent page", rec: f.get(AuthorizePath, f.authorizeQuery(), false)},
		{name: "decision", rec: f.post(AuthorizePath, url.Values{"request": {request}, "decision": {"approve"}}, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", tc.rec.Code)
			}
			if !strings.Contains(tc.rec.Body.String(), "tailnet") {
				t.Errorf("page does not say to use the tailnet:\n%s", tc.rec.Body.String())
			}
		})
	}
	if got := f.identify.count(); got != calls {
		t.Errorf("identify was called %d more times over Funnel", got-calls)
	}
	if _, ok := f.server.pending.take(request); !ok {
		t.Error("a Funnel request consumed the pending authorization")
	}
}

func TestAuthorizeRefusalsBeforeRedirect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(f *fixture, q url.Values)
		status int
		reason string
	}{
		{
			name:   "client id missing",
			edit:   func(_ *fixture, q url.Values) { q.Del("client_id") },
			status: http.StatusBadRequest,
			reason: "Unknown client",
		},
		{
			name:   "client id not https",
			edit:   func(_ *fixture, q url.Values) { q.Set("client_id", "http://client.example.com/client") },
			status: http.StatusBadRequest,
			reason: "Unknown client",
		},
		{
			name:   "client document missing",
			edit:   func(f *fixture, q url.Values) { q.Set("client_id", "https://client.invalid/client") },
			status: http.StatusBadRequest,
			reason: "Unknown client",
		},
		{
			name:   "redirect uri not registered",
			edit:   func(_ *fixture, q url.Values) { q.Set("redirect_uri", "https://client.example.com/other") },
			status: http.StatusBadRequest,
			reason: "Redirect not registered",
		},
		{
			name:   "redirect uri differing by port",
			edit:   func(_ *fixture, q url.Values) { q.Set("redirect_uri", "https://client.example.com:8443/callback") },
			status: http.StatusBadRequest,
			reason: "Redirect not registered",
		},
		{
			name:   "redirect uri omitted with several registered",
			edit:   func(_ *fixture, q url.Values) { q.Del("redirect_uri") },
			status: http.StatusBadRequest,
			reason: "Redirect not registered",
		},
		{
			name:   "repeated parameter",
			edit:   func(_ *fixture, q url.Values) { q.Add("redirect_uri", callback) },
			status: http.StatusBadRequest,
			reason: "repeats the redirect_uri",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			query := f.authorizeQuery()
			tc.edit(f, query)
			rec := f.get(AuthorizePath, query, true)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if rec.Header().Get("Location") != "" {
				t.Errorf("redirected to %q before the redirect_uri was validated", rec.Header().Get("Location"))
			}
			if !strings.Contains(rec.Body.String(), tc.reason) {
				t.Errorf("page does not say %q:\n%s", tc.reason, rec.Body.String())
			}
			if got := f.identify.count(); got != 0 {
				t.Errorf("identify called %d times for a request refused on its parameters", got)
			}
		})
	}
}

func TestAuthorizeRefusalsThroughRedirect(t *testing.T) {
	for _, tc := range []struct {
		name     string
		edit     func(q url.Values)
		identify *fakeIdentify
		want     string
	}{
		{
			name: "response type token",
			edit: func(q url.Values) { q.Set("response_type", "token") },
			want: "unsupported_response_type",
		},
		{
			name: "no pkce",
			edit: func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
			want: "invalid_request",
		},
		{
			name: "plain pkce",
			edit: func(q url.Values) { q.Set("code_challenge_method", "plain"); q.Set("code_challenge", verifier) },
			want: "invalid_request",
		},
		{
			name: "malformed challenge",
			edit: func(q url.Values) { q.Set("code_challenge", "short") },
			want: "invalid_request",
		},
		{
			name: "unsupported scope",
			edit: func(q url.Values) { q.Set("scope", "openid admin") },
			want: "invalid_scope",
		},
		{
			name: "no resource",
			edit: func(q url.Values) { q.Del("resource") },
			want: "invalid_target",
		},
		{
			name: "resource for an unconfigured upstream",
			edit: func(q url.Values) { q.Set("resource", origin+"/mcp/missing") },
			want: "invalid_target",
		},
		{
			name: "resource differing by trailing slash",
			edit: func(q url.Values) { q.Set("resource", testResource+"/") },
			want: "invalid_target",
		},
		{
			name: "resource at another origin",
			edit: func(q url.Values) { q.Set("resource", "https://other.example.ts.net/mcp/docs") },
			want: "invalid_target",
		},
		{
			name:     "peer cannot be identified",
			edit:     func(url.Values) {},
			identify: &fakeIdentify{err: errors.New("peer not found")},
			want:     "access_denied",
		},
		{
			name: "tagged node",
			edit: func(url.Values) {},
			identify: &fakeIdentify{who: &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{Name: "server.example.ts.net.", Tags: []string{"tag:server"}},
				UserProfile: &tailcfg.UserProfile{ID: 1, LoginName: "tagged-devices"},
			}},
			want: "access_denied",
		},
		{
			name:     "no user behind the node",
			edit:     func(url.Values) {},
			identify: &fakeIdentify{who: &apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{}}},
			want:     "access_denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.identify != nil {
				f.server.identify = tc.identify.identify
			}
			query := f.authorizeQuery()
			tc.edit(query)
			rec := f.get(AuthorizePath, query, true)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
			}
			location := redirectQuery(t, rec, callback)
			if got := location.Get("error"); got != tc.want {
				t.Errorf("error = %q, want %q (%s)", got, tc.want, location.Get("error_description"))
			}
			if got := location.Get("state"); got != "xyz" {
				t.Errorf("state = %q, want xyz", got)
			}
			if location.Get("code") != "" {
				t.Error("an error redirect carries a code")
			}
		})
	}
}

func TestAuthorizeDefaultsAndLoopback(t *testing.T) {
	f := newFixture(t)
	query := f.authorizeQuery()
	query.Del("scope")
	query.Del("state")
	query.Set("redirect_uri", "http://127.0.0.1:53421/cb")

	request := f.consent(t, query)
	rec := f.post(AuthorizePath, url.Values{"request": {request}, "decision": {"approve"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /authorize = %d: %s", rec.Code, rec.Body.String())
	}
	location := redirectQuery(t, rec, "http://127.0.0.1:53421/cb")
	if location.Has("state") {
		t.Error("redirect carries a state the request never sent")
	}
	form := f.codeForm(location.Get("code"))
	form.Set("redirect_uri", "http://127.0.0.1:53421/cb")
	issued := f.redeem(t, form)
	if issued.Scope != "openid email" {
		t.Errorf("scope = %q, want every supported scope by default", issued.Scope)
	}
}

func TestDecisionRefusals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		form      func(f *fixture, request string) url.Values
		identify  *fakeIdentify
		advance   time.Duration
		status    int
		wantError string
		// keepsPending marks a refusal that never reached the pending
		// request, which therefore stays answerable.
		keepsPending bool
	}{
		{
			name: "denied",
			form: func(_ *fixture, request string) url.Values {
				return url.Values{"request": {request}, "decision": {"deny"}}
			},
			status:    http.StatusSeeOther,
			wantError: "access_denied",
		},
		{
			name: "no decision",
			form: func(_ *fixture, request string) url.Values {
				return url.Values{"request": {request}}
			},
			status:    http.StatusSeeOther,
			wantError: "access_denied",
		},
		{
			name: "unknown request",
			form: func(*fixture, string) url.Values {
				return url.Values{"request": {"nope"}, "decision": {"approve"}}
			},
			status:       http.StatusBadRequest,
			keepsPending: true,
		},
		{
			name: "expired request",
			form: func(_ *fixture, request string) url.Values {
				return url.Values{"request": {request}, "decision": {"approve"}}
			},
			advance: pendingTTL,
			status:  http.StatusBadRequest,
		},
		{
			name: "another person answers",
			form: func(_ *fixture, request string) url.Values {
				return url.Values{"request": {request}, "decision": {"approve"}}
			},
			identify: &fakeIdentify{who: &apitype.WhoIsResponse{
				Node:        &tailcfg.Node{Name: "other.example.ts.net."},
				UserProfile: &tailcfg.UserProfile{ID: 999, LoginName: "someone@example.com"},
			}},
			status:    http.StatusSeeOther,
			wantError: "access_denied",
		},
		{
			name: "person no longer identifiable",
			form: func(_ *fixture, request string) url.Values {
				return url.Values{"request": {request}, "decision": {"approve"}}
			},
			identify:  &fakeIdentify{err: errors.New("peer not found")},
			status:    http.StatusSeeOther,
			wantError: "access_denied",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			request := f.consent(t, f.authorizeQuery())
			if tc.identify != nil {
				f.server.identify = tc.identify.identify
			}
			f.clock.Advance(tc.advance)

			rec := f.post(AuthorizePath, tc.form(f, request), true)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.status, rec.Body.String())
			}
			if tc.wantError != "" {
				location := redirectQuery(t, rec, callback)
				if got := location.Get("error"); got != tc.wantError {
					t.Errorf("error = %q, want %q", got, tc.wantError)
				}
			}
			if f.server.codes.len() != 0 {
				t.Error("a refused decision minted a code")
			}
			if tc.keepsPending {
				return
			}
			// The request is consumed either way, so it cannot be answered
			// twice.
			rec = f.post(AuthorizePath, url.Values{"request": {request}, "decision": {"approve"}}, true)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("a second answer to the same request = %d, want 400", rec.Code)
			}
		})
	}
}

func TestTokenRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		form    func(f *fixture, code string) url.Values
		headers map[string]string
		advance time.Duration
		want    string
	}{
		{
			name: "client secret offered",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("client_secret", "hunter2")
				return form
			},
			want: "invalid_client",
		},
		{
			name:    "basic auth offered",
			form:    func(f *fixture, code string) url.Values { return f.codeForm(code) },
			headers: map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("id:secret"))},
			want:    "invalid_client",
		},
		{
			name: "client id not a metadata url",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("client_id", "my-app")
				return form
			},
			want: "invalid_client",
		},
		{
			name: "unsupported grant type",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("grant_type", "client_credentials")
				return form
			},
			want: "unsupported_grant_type",
		},
		{
			name:    "expired code",
			form:    func(f *fixture, code string) url.Values { return f.codeForm(code) },
			advance: codeTTL,
			want:    "invalid_grant",
		},
		{
			name: "another client's code",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("client_id", "https://other.example.com/client")
				return form
			},
			want: "invalid_grant",
		},
		{
			name: "redirect uri differs",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("redirect_uri", loopbackCB)
				return form
			},
			want: "invalid_grant",
		},
		{
			name: "redirect uri omitted",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Del("redirect_uri")
				return form
			},
			want: "invalid_grant",
		},
		{
			name: "wrong verifier",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("code_verifier", strings.Repeat("b", 43))
				return form
			},
			want: "invalid_grant",
		},
		{
			name: "verifier omitted",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Del("code_verifier")
				return form
			},
			want: "invalid_grant",
		},
		{
			name: "resource differs",
			form: func(f *fixture, code string) url.Values {
				form := f.codeForm(code)
				form.Set("resource", origin+"/mcp/other")
				return form
			},
			want: "invalid_target",
		},
		{
			name: "refresh token unknown",
			form: func(f *fixture, _ string) url.Values {
				return url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "refresh_token": {strings.Repeat("c", 43)}}
			},
			want: "invalid_grant",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			code := f.authorize(t)
			f.clock.Advance(tc.advance)

			req := httptest.NewRequest(http.MethodPost, TokenPath, strings.NewReader(tc.form(f, code).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			rec := httptest.NewRecorder()
			f.server.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
			if got, _ := oauthError(t, rec); got != tc.want {
				t.Errorf("error = %q, want %q: %s", got, tc.want, rec.Body.String())
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

// A code that reaches redemption is consumed whether or not the
// redemption succeeds, so a client that gets the verifier wrong
// re-authorizes.
func TestRefusedRedemptionConsumesTheCode(t *testing.T) {
	f := newFixture(t)
	code := f.authorize(t)
	wrong := f.codeForm(code)
	wrong.Set("code_verifier", strings.Repeat("b", 43))
	if rec := f.post(TokenPath, wrong, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong verifier = %d", rec.Code)
	}
	rec := f.post(TokenPath, f.codeForm(code), false)
	if got, _ := oauthError(t, rec); got != "invalid_grant" {
		t.Errorf("redeeming after a refused attempt = %d %s, want invalid_grant", rec.Code, got)
	}
}

func TestRefreshRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(f *fixture, form url.Values)
		want string
	}{
		{
			name: "another client",
			edit: func(_ *fixture, form url.Values) { form.Set("client_id", "https://other.example.com/client") },
			want: "invalid_grant",
		},
		{
			name: "scope not granted",
			edit: func(_ *fixture, form url.Values) { form.Set("scope", "openid profile") },
			want: "invalid_scope",
		},
		{
			name: "resource differs",
			edit: func(_ *fixture, form url.Values) { form.Set("resource", origin+"/mcp/other") },
			want: "invalid_target",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			issued := f.redeem(t, f.codeForm(f.authorize(t)))
			form := url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "refresh_token": {issued.RefreshToken}}
			tc.edit(f, form)

			rec := f.post(TokenPath, form, false)
			if got, _ := oauthError(t, rec); rec.Code != http.StatusBadRequest || got != tc.want {
				t.Errorf("refresh = %d %s, want 400 %s", rec.Code, got, tc.want)
			}
		})
	}
}

// A refresh refused for its own scope or resource leaves the token in place,
// so a client that mistyped a parameter corrects it instead of starting over.
func TestRefreshRefusedForItsParametersKeepsTheToken(t *testing.T) {
	f := newFixture(t)
	issued := f.redeem(t, f.codeForm(f.authorize(t)))
	form := url.Values{"grant_type": {"refresh_token"}, "client_id": {f.clientID}, "refresh_token": {issued.RefreshToken}}

	form.Set("scope", "openid profile")
	if rec := f.post(TokenPath, form, false); rec.Code != http.StatusBadRequest {
		t.Fatalf("refresh with an ungranted scope = %d, want 400", rec.Code)
	}
	form.Set("scope", "openid")
	if refreshed := f.redeem(t, form); refreshed.RefreshToken == issued.RefreshToken {
		t.Error("the retried refresh did not rotate the token")
	}
}

// A code replay after the client has refreshed still revokes every token the
// grant produced, including the rotated pair.
func TestCodeReplayRevokesRotatedTokens(t *testing.T) {
	f := newFixture(t)
	code := f.authorize(t)
	issued := f.redeem(t, f.codeForm(code))
	refreshed := f.redeem(t, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {issued.RefreshToken},
	})

	if rec := f.post(TokenPath, f.codeForm(code), false); rec.Code != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", rec.Code)
	}
	if _, err := f.tokens.Verify(t.Context(), refreshed.AccessToken, testResource); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("rotated access token survived a code replay: %v", err)
	}
	rec := f.post(TokenPath, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {refreshed.RefreshToken},
	}, false)
	if errCode, _ := oauthError(t, rec); errCode != "invalid_grant" {
		t.Errorf("rotated refresh token survived a code replay: %d %s", rec.Code, errCode)
	}
}

func TestRefreshNarrowsScope(t *testing.T) {
	f := newFixture(t)
	issued := f.redeem(t, f.codeForm(f.authorize(t)))
	narrowed := f.redeem(t, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {f.clientID},
		"refresh_token": {issued.RefreshToken},
		"scope":         {"openid"},
	})
	if narrowed.Scope != "openid" {
		t.Errorf("scope = %q, want openid", narrowed.Scope)
	}
	id, err := f.tokens.Verify(t.Context(), narrowed.AccessToken, testResource)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got := id.Claims["scope"]; got != "openid" {
		t.Errorf("scope claim = %v, want openid", got)
	}
}

func TestMetadata(t *testing.T) {
	f := newFixture(t)
	for _, path := range []string{MetadataPath, OpenIDMetadataPath, MetadataPath + "/mcp/docs", OpenIDMetadataPath + "/mcp/docs"} {
		t.Run(path, func(t *testing.T) {
			rec := f.get(path, nil, false)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q", got)
			}
			var got map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode: %v", err)
			}
			want := map[string]any{
				"issuer":                                origin,
				"authorization_endpoint":                origin + AuthorizePath,
				"token_endpoint":                        origin + TokenPath,
				"scopes_supported":                      []any{"openid", "email"},
				"response_types_supported":              []any{"code"},
				"grant_types_supported":                 []any{"authorization_code", "refresh_token"},
				"token_endpoint_auth_methods_supported": []any{"none"},
				"code_challenge_methods_supported":      []any{"S256"},
				"resource_indicators_supported":         true,
				"client_id_metadata_document_supported": true,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("metadata mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHandles(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		path string
		want bool
	}{
		{path: AuthorizePath, want: true},
		{path: TokenPath, want: true},
		{path: MetadataPath, want: true},
		{path: OpenIDMetadataPath, want: true},
		{path: MetadataPath + "/mcp/docs", want: true},
		{path: OpenIDMetadataPath + "/mcp/other", want: true},
		{path: MetadataPath + "/mcp/missing"},
		{path: MetadataPath + "/mcp/"},
		{path: "/register"},
		{path: "/mcp/docs"},
		{path: "/"},
		{path: AuthorizePath + "/"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if got := f.server.Handles(tc.path); got != tc.want {
				t.Errorf("Handles(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestMethodsRefused(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name   string
		method string
		path   string
		allow  string
	}{
		{name: "put authorize", method: http.MethodPut, path: AuthorizePath, allow: "GET, POST"},
		{name: "get token", method: http.MethodGet, path: TokenPath, allow: "POST"},
		{name: "post metadata", method: http.MethodPost, path: MetadataPath, allow: "GET, HEAD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			f.server.ServeHTTP(rec, onTailnet(httptest.NewRequest(tc.method, tc.path, nil)))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("status = %d, want 405", rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow = %q, want %q", got, tc.allow)
			}
		})
	}
}

func TestEscapedPathRefused(t *testing.T) {
	f := newFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/%61uthorize", nil)
	if req.URL.Path != AuthorizePath || req.URL.EscapedPath() == AuthorizePath {
		t.Fatalf("request path decodes to %q with escaped form %q", req.URL.Path, req.URL.EscapedPath())
	}
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, onTailnet(req))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestNewRequiresCollaborators(t *testing.T) {
	urls, err := resource.NewURLs(testFQDN, 443)
	if err != nil {
		t.Fatal(err)
	}
	complete := Options{
		Resources:   urls,
		Tokens:      auth.NewTokens(),
		Identify:    (&fakeIdentify{}).identify,
		Clients:     cimd.NewFetcher(http.DefaultClient),
		HasUpstream: func(string) bool { return true },
	}
	for _, tc := range []struct {
		name string
		edit func(o *Options)
	}{
		{name: "resources", edit: func(o *Options) { o.Resources = nil }},
		{name: "tokens", edit: func(o *Options) { o.Tokens = nil }},
		{name: "identify", edit: func(o *Options) { o.Identify = nil }},
		{name: "clients", edit: func(o *Options) { o.Clients = nil }},
		{name: "upstream check", edit: func(o *Options) { o.HasUpstream = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := complete
			tc.edit(&opts)
			if _, err := New(opts); err == nil {
				t.Error("New accepted incomplete options")
			}
		})
	}
	if _, err := New(complete); err != nil {
		t.Errorf("New refused complete options: %v", err)
	}
}

func TestResolveRedirectURI(t *testing.T) {
	registered := []string{callback, loopbackCB, "http://localhost:3000/cb?app=1"}
	for _, tc := range []struct {
		name      string
		requested string
		want      string
		ok        bool
	}{
		{name: "exact match", requested: callback, want: callback, ok: true},
		{name: "loopback any port", requested: "http://127.0.0.1:61234/cb", want: "http://127.0.0.1:61234/cb", ok: true},
		{name: "localhost port change keeps query", requested: "http://localhost:4000/cb?app=1", want: "http://localhost:4000/cb?app=1", ok: true},
		{name: "loopback path differs", requested: "http://127.0.0.1:61234/other"},
		{name: "loopback host differs", requested: "http://localhost:61234/cb"},
		{name: "loopback query differs", requested: "http://localhost:4000/cb?app=2"},
		{name: "https port change", requested: "https://client.example.com:8443/callback"},
		{name: "trailing slash", requested: callback + "/"},
		{name: "case differs", requested: "https://client.example.com/Callback"},
		{name: "omitted with several registered"},
		{name: "not registered", requested: "https://attacker.example.com/callback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := resolveRedirectURI(tc.requested, registered)
			if ok != tc.ok || got != tc.want {
				t.Errorf("resolveRedirectURI(%q) = %q, %v, want %q, %v", tc.requested, got, ok, tc.want, tc.ok)
			}
		})
	}
	if got, ok := resolveRedirectURI("", []string{callback}); !ok || got != callback {
		t.Errorf("omitted redirect_uri with one registered = %q, %v", got, ok)
	}
}

func TestPKCE(t *testing.T) {
	for _, tc := range []struct {
		name      string
		challenge string
		verifier  string
		want      bool
	}{
		{name: "matching pair", challenge: challenge, verifier: verifier, want: true},
		{name: "longest verifier", challenge: s256(strings.Repeat("z", 128)), verifier: strings.Repeat("z", 128), want: true},
		{name: "wrong verifier", challenge: challenge, verifier: strings.Repeat("a", 43)},
		{name: "verifier too short", challenge: s256("short"), verifier: "short"},
		{name: "verifier too long", challenge: s256(strings.Repeat("z", 129)), verifier: strings.Repeat("z", 129)},
		{name: "verifier with reserved characters", challenge: s256(strings.Repeat("a", 42) + "+"), verifier: strings.Repeat("a", 42) + "+"},
		{name: "empty verifier", challenge: challenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyPKCE(tc.challenge, tc.verifier); got != tc.want {
				t.Errorf("verifyPKCE = %v, want %v", got, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		name      string
		challenge string
		want      bool
	}{
		{name: "s256 digest", challenge: challenge, want: true},
		{name: "too short", challenge: strings.Repeat("a", 42)},
		{name: "too long", challenge: strings.Repeat("a", 44)},
		{name: "padded base64", challenge: strings.Repeat("a", 42) + "="},
		{name: "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validCodeChallenge(tc.challenge); got != tc.want {
				t.Errorf("validCodeChallenge(%q) = %v, want %v", tc.challenge, got, tc.want)
			}
		})
	}
}

func TestTableBoundsAndExpiry(t *testing.T) {
	clock := &testClock{now: time.Unix(1_800_000_000, 0)}
	table := newTable[string](2, time.Minute, clock.Now)

	a, ok := table.put("a")
	if !ok {
		t.Fatal("put refused an empty table")
	}
	if _, ok := table.put("b"); !ok {
		t.Fatal("put refused a table with room")
	}
	if _, ok := table.put("c"); ok {
		t.Error("put accepted a full table of live entries")
	}
	clock.Advance(time.Minute)
	if _, ok := table.put("c"); !ok {
		t.Error("put refused after every entry expired")
	}
	if _, ok := table.take(a); ok {
		t.Error("take returned an expired entry")
	}
	if table.len() != 1 {
		t.Errorf("table holds %d entries, want 1", table.len())
	}
	if _, ok := table.take("never"); ok {
		t.Error("take returned an unknown handle")
	}
}
