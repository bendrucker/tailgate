package router

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/proxy"
	"github.com/bendrucker/tailgate/internal/resource"
)

const (
	testFQDN      = "tailgate.example.ts.net"
	testPort      = 443
	testIssuer    = "https://idp.example.ts.net"
	testOrigin    = "https://tailgate.example.ts.net"
	httpUpstream  = "docs"
	stdioUpstream = "files"
)

// fakeVerifier resolves tokens registered by the test and rejects the rest, so
// a test never depends on a live issuer.
type fakeVerifier struct {
	mu         sync.Mutex
	identities map[string]auth.Identity
	err        error
	resources  []string
}

func (v *fakeVerifier) Verify(_ context.Context, token, res string) (auth.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.resources = append(v.resources, res)
	if v.err != nil {
		return auth.Identity{}, v.err
	}
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

// fakeAuthorizer allows the subject-upstream pairs the test grants.
type fakeAuthorizer struct {
	mu    sync.Mutex
	allow map[string]bool
}

func (a *fakeAuthorizer) Authorize(id auth.Identity, upstream string) auth.Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	decision := auth.Decision{Identity: id, Upstream: upstream, Reason: auth.ReasonNoMatch}
	if a.allow[id.Subject+"@"+upstream] {
		decision.Allow = true
		decision.Rule = "policy[0].allow[0]"
		decision.Reason = auth.ReasonMatched
	}
	return decision
}

// fakeTransport stands in for a proxy.Transport and records what reached it.
type fakeTransport struct {
	mu       sync.Mutex
	requests []*http.Request
	shutdown bool
	closed   bool

	handler http.HandlerFunc
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{}
}

func (t *fakeTransport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	t.requests = append(t.requests, r)
	handler := t.handler
	t.mu.Unlock()

	if handler != nil {
		handler(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
}

func (t *fakeTransport) Shutdown(context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.shutdown = true
	return nil
}

func (t *fakeTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

func (t *fakeTransport) served() []*http.Request {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*http.Request(nil), t.requests...)
}

func (t *fakeTransport) count() int { return len(t.served()) }

var _ proxy.Transport = (*fakeTransport)(nil)

// auditRecord is one decision as the audit package rendered it.
type auditRecord struct {
	Level    string
	Outcome  string
	Subject  string
	Email    string
	Upstream string
	Reason   string
	Rule     string
}

type auditCollector struct {
	mu      sync.Mutex
	records []auditRecord
}

func (c *auditCollector) Enabled(context.Context, slog.Level) bool { return true }

func (c *auditCollector) Handle(_ context.Context, r slog.Record) error {
	record := auditRecord{Level: r.Level.String()}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case audit.KeyOutcome:
			record.Outcome = a.Value.String()
		case audit.KeySubject:
			record.Subject = a.Value.String()
		case audit.KeyEmail:
			record.Email = a.Value.String()
		case audit.KeyUpstream:
			record.Upstream = a.Value.String()
		case audit.KeyReason:
			record.Reason = a.Value.String()
		case audit.KeyRule:
			record.Rule = a.Value.String()
		}
		return true
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
	return nil
}

func (c *auditCollector) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *auditCollector) WithGroup(string) slog.Handler      { return c }

func (c *auditCollector) decisions() []auditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]auditRecord(nil), c.records...)
}

type harness struct {
	router     *Router
	urls       *resource.URLs
	verifier   *fakeVerifier
	authorizer *fakeAuthorizer
	httpUp     *fakeTransport
	stdioUp    *fakeTransport
	audit      *auditCollector
}

func newHarness(t *testing.T, configure ...func(*Options)) *harness {
	t.Helper()

	urls, err := resource.NewURLs(testFQDN, testPort)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	metadata, err := resource.NewHandler(urls, testIssuer, []string{httpUpstream, stdioUpstream})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	h := &harness{
		urls:       urls,
		verifier:   &fakeVerifier{identities: make(map[string]auth.Identity)},
		authorizer: &fakeAuthorizer{allow: make(map[string]bool)},
		httpUp:     newFakeTransport(),
		stdioUp:    newFakeTransport(),
		audit:      &auditCollector{},
	}

	opts := Options{
		Upstreams: []Upstream{
			{Name: httpUpstream, Transport: h.httpUp},
			{Name: stdioUpstream, Transport: h.stdioUp, TransportManagesSessions: true},
		},
		Resources:      urls,
		Metadata:       metadata,
		Verifier:       h.verifier,
		Authorizer:     h.authorizer,
		Audit:          audit.New(slog.New(h.audit)),
		AllowedOrigins: []string{testOrigin},
		Logger:         slog.New(slog.DiscardHandler),
	}
	for _, c := range configure {
		c(&opts)
	}

	router, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.router = router
	return h
}

// grant registers a token that verifies to subject and is allowed on upstream.
func (h *harness) grant(token, subject, email string, upstreams ...string) {
	h.verifier.mu.Lock()
	h.verifier.identities[token] = auth.Identity{Subject: subject, Email: email}
	h.verifier.mu.Unlock()

	h.authorizer.mu.Lock()
	defer h.authorizer.mu.Unlock()
	for _, upstream := range upstreams {
		h.authorizer.allow[subject+"@"+upstream] = true
	}
}

func (h *harness) serve(req *http.Request) *http.Response {
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec.Result()
}

// post builds an authorized-looking POST to an upstream endpoint.
func post(target, token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

func TestRouteRejectsHostilePaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "empty upstream name", target: "/mcp/"},
		{name: "double slash before name", target: "/mcp//docs"},
		{name: "traversal out of the prefix", target: "/mcp/docs/../files"},
		{name: "encoded traversal", target: "/mcp/%2e%2e/%2e%2e/etc/passwd"},
		{name: "encoded upstream name", target: "/mcp/%64ocs"},
		{name: "encoded separator in name", target: "/mcp/docs%2Ffiles"},
		{name: "trailing slash", target: "/mcp/docs/"},
		{name: "trailing segment", target: "/mcp/docs/messages"},
		{name: "dot segment", target: "/mcp/./docs"},
		{name: "unknown upstream", target: "/mcp/nope"},
		{name: "prefix without separator", target: "/mcpdocs"},
		{name: "bare prefix", target: "/mcp"},
		{name: "root", target: "/"},
		{name: "case mismatched name", target: "/mcp/Docs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream, stdioUpstream)

			resp := h.serve(post(tc.target, "good"))
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
			}
			if got := h.httpUp.count() + h.stdioUp.count(); got != 0 {
				t.Errorf("transports served %d requests, want 0", got)
			}
		})
	}
}

func TestRouteServesMetadataWithoutAuth(t *testing.T) {
	h := newHarness(t)

	resp := h.serve(httptest.NewRequest(http.MethodGet, h.urls.MetadataPath(httpUpstream), nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var doc resource.Metadata
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	want := resource.Metadata{
		Resource:               h.urls.ResourceURL(httpUpstream),
		AuthorizationServers:   []string{testIssuer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"openid", "email"},
	}
	if diff := cmp.Diff(want, doc); diff != "" {
		t.Errorf("metadata mismatch (-want +got):\n%s", diff)
	}
	if h.httpUp.count() != 0 {
		t.Error("metadata request reached the transport")
	}
}

// TestDiscoveryFollowsTheChallengeItServes walks the loop a fresh MCP client
// walks: an unauthenticated request, then the URL the challenge names, fetched
// from the same Router. It fails if the advertised metadata URL and the mounted
// well-known route ever drift apart, or if the audience in the document differs
// from the one the verifier is asked to check the token against.
func TestDiscoveryFollowsTheChallengeItServes(t *testing.T) {
	for _, name := range []string{httpUpstream, stdioUpstream} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)

			challenged := h.serve(post("/mcp/"+name, ""))
			if challenged.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", challenged.StatusCode)
			}
			metadataURL, ok := challengeParam(challenged.Header.Get("WWW-Authenticate"), "resource_metadata")
			if !ok {
				t.Fatalf("no resource_metadata in %q", challenged.Header.Get("WWW-Authenticate"))
			}

			target, err := url.Parse(metadataURL)
			if err != nil {
				t.Fatalf("parse resource_metadata %q: %v", metadataURL, err)
			}
			if target.Host != testFQDN {
				t.Errorf("resource_metadata host = %q, want %q", target.Host, testFQDN)
			}

			discovered := h.serve(httptest.NewRequest(http.MethodGet, target.Path, nil))
			if discovered.StatusCode != http.StatusOK {
				t.Fatalf("fetching %s: status = %d, want 200", target.Path, discovered.StatusCode)
			}
			var doc resource.Metadata
			if err := json.NewDecoder(discovered.Body).Decode(&doc); err != nil {
				t.Fatalf("decode metadata: %v", err)
			}

			h.grant("good", "42", "user@example.com", name)
			if resp := h.serve(post("/mcp/"+name, "good")); resp.StatusCode != http.StatusOK {
				t.Fatalf("authorized request: status = %d, want 200", resp.StatusCode)
			}
			audiences := h.verifier.audiences()
			if len(audiences) != 1 || audiences[0] != doc.Resource {
				t.Errorf("verified audience = %v, want the document's resource %q", audiences, doc.Resource)
			}
		})
	}
}

// challengeParam reads one quoted parameter out of a WWW-Authenticate value the
// way a client would, rather than reusing the builder that produced it.
func challengeParam(challenge, name string) (string, bool) {
	scheme, params, ok := strings.Cut(challenge, " ")
	if !ok || scheme != "Bearer" {
		return "", false
	}
	for _, param := range strings.Split(params, ", ") {
		key, value, ok := strings.Cut(param, "=")
		if !ok || key != name {
			continue
		}
		return strings.Trim(value, `"`), true
	}
	return "", false
}

func TestRouteRefusesUnknownMetadataDocument(t *testing.T) {
	h := newHarness(t)

	resp := h.serve(httptest.NewRequest(http.MethodGet, resource.MetadataPathPrefix+"/mcp/nope", nil))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
	if h.httpUp.count() != 0 {
		t.Error("well-known request reached the transport")
	}
}

func TestAllowStripsCredentialsAndInjectsIdentity(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)

	var seen *http.Request
	var identity auth.Identity
	var found bool
	h.httpUp.handler = func(w http.ResponseWriter, r *http.Request) {
		seen = r
		identity, found = auth.IdentityFrom(r.Context())
		w.WriteHeader(http.StatusAccepted)
	}

	req := post("/mcp/"+httpUpstream, "good")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("x-forwarded-host", "evil.example.com")
	req.Header.Set("Forwarded", "for=203.0.113.9")
	req.Header.Set("Proxy-Authorization", "Basic Zm9vOmJhcg==")
	req.Header.Set(IdentityHeaderPrefix+"Subject", "999")
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	req.Header.Set("Origin", testOrigin)

	resp := h.serve(req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	if seen == nil {
		t.Fatal("transport never served the request")
	}
	if !found {
		t.Fatal("transport saw no identity in context")
	}
	if diff := cmp.Diff(auth.Identity{Subject: "42", Email: "user@example.com"}, identity); diff != "" {
		t.Errorf("identity mismatch (-want +got):\n%s", diff)
	}
	for _, header := range []string{
		"Authorization",
		"Proxy-Authorization",
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		IdentityHeaderPrefix + "Subject",
	} {
		if got := seen.Header.Get(header); got != "" {
			t.Errorf("header %s reached the transport as %q", header, got)
		}
	}
	if got := seen.Header.Get("Mcp-Protocol-Version"); got != "2025-11-25" {
		t.Errorf("Mcp-Protocol-Version = %q, want it forwarded", got)
	}
	if seen.URL.Path != "/" {
		t.Errorf("upstream path = %q, want %q", seen.URL.Path, "/")
	}
	if got := req.Header.Get("Authorization"); got == "" {
		t.Error("stripping mutated the inbound request instead of a clone")
	}
	if got := h.verifier.audiences(); len(got) != 1 || got[0] != h.urls.ResourceURL(httpUpstream) {
		t.Errorf("verified audiences = %v, want [%s]", got, h.urls.ResourceURL(httpUpstream))
	}
}

func TestAllowIsAudited(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)

	if resp := h.serve(post("/mcp/"+httpUpstream, "good")); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	want := []auditRecord{{
		Level:    slog.LevelInfo.String(),
		Outcome:  audit.OutcomeAllow,
		Subject:  "42",
		Email:    "user@example.com",
		Upstream: httpUpstream,
		Reason:   auth.ReasonMatched,
		Rule:     "policy[0].allow[0]",
	}}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestPolicyDenialIsForbiddenAndAudited(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", stdioUpstream)

	resp := h.serve(post("/mcp/"+httpUpstream, "good"))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Error("a policy denial challenged the client to re-authenticate")
	}
	if h.httpUp.count() != 0 {
		t.Error("denied request reached the transport")
	}
	want := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Subject:  "42",
		Email:    "user@example.com",
		Upstream: httpUpstream,
		Reason:   auth.ReasonNoMatch,
	}}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestOriginValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		status int
	}{
		{name: "absent origin from a non browser client", origin: "", status: http.StatusOK},
		{name: "canonical funnel origin", origin: testOrigin, status: http.StatusOK},
		{name: "canonical origin with default port", origin: "https://" + testFQDN + ":443", status: http.StatusOK},
		{name: "uppercase host", origin: "https://" + strings.ToUpper(testFQDN), status: http.StatusOK},
		{name: "attacker origin", origin: "https://evil.example.com", status: http.StatusForbidden},
		{name: "http scheme downgrade", origin: "http://" + testFQDN, status: http.StatusForbidden},
		{name: "non default port", origin: "https://" + testFQDN + ":8443", status: http.StatusForbidden},
		{name: "null origin", origin: "null", status: http.StatusForbidden},
		{name: "host prefix", origin: "https://" + testFQDN + ".evil.example.com", status: http.StatusForbidden},
		{name: "origin with a path", origin: testOrigin + "/mcp/docs", status: http.StatusForbidden},
		{name: "empty scheme", origin: "//" + testFQDN, status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.grant("good", "42", "user@example.com", httpUpstream)

			req := post("/mcp/"+httpUpstream, "good")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			resp := h.serve(req)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if tc.status == http.StatusForbidden && h.httpUp.count() != 0 {
				t.Error("request with a rejected origin reached the transport")
			}
		})
	}
}

func TestOriginRejectionPrecedesRouting(t *testing.T) {
	h := newHarness(t)

	req := httptest.NewRequest(http.MethodGet, h.urls.MetadataPath(httpUpstream), nil)
	req.Header.Set("Origin", "https://evil.example.com")
	if resp := h.serve(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("metadata status = %d, want 403", resp.StatusCode)
	}
}

// TestOriginDenialAuditsOnlyConfiguredUpstreams defends the decision log
// against an unauthenticated caller: the upstream segment is theirs to choose,
// so it may only reach the audit record once it names a configured upstream.
func TestOriginDenialAuditsOnlyConfiguredUpstreams(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		name     string
		target   string
		upstream string
	}{
		{name: "configured upstream", target: "/mcp/" + httpUpstream, upstream: httpUpstream},
		{name: "unconfigured upstream name", target: "/mcp/" + strings.Repeat("a", 4096)},
		{name: "hostile path", target: "/mcp/%2e%2e/etc/passwd"},
		{name: "metadata document", target: h.urls.MetadataPath(httpUpstream)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := post(tc.target, "")
			req.Header.Set("Origin", "https://evil.example.com")
			if resp := h.serve(req); resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}

			want := auditRecord{
				Level:    slog.LevelWarn.String(),
				Outcome:  audit.OutcomeDeny,
				Upstream: tc.upstream,
				Reason:   ReasonOriginNotAllowed,
			}
			decisions := h.audit.decisions()
			if diff := cmp.Diff(want, decisions[len(decisions)-1]); diff != "" {
				t.Errorf("audit mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPanicInTransportBecomesInternalServerError(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)
	h.httpUp.handler = func(http.ResponseWriter, *http.Request) {
		panic("upstream exploded")
	}

	resp := h.serve(post("/mcp/"+httpUpstream, "good"))
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "exploded") {
		t.Error("panic value leaked into the response body")
	}
}

func TestPanicAfterResponseStartedKeepsStatus(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)
	h.httpUp.handler = func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		panic("late failure")
	}

	if resp := h.serve(post("/mcp/"+httpUpstream, "good")); resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want the already-sent 202", resp.StatusCode)
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    io.Reader
		status  int
		reached bool
	}{
		{
			name:   "declared length over the cap",
			body:   strings.NewReader(strings.Repeat("a", 200)),
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name:   "undeclared length over the cap",
			body:   io.NopCloser(strings.NewReader(strings.Repeat("a", 200))),
			status: http.StatusRequestEntityTooLarge,
		},
		{
			name:    "body within the cap",
			body:    strings.NewReader(strings.Repeat("a", 16)),
			status:  http.StatusOK,
			reached: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(o *Options) { o.MaxBodyBytes = 64 })
			h.grant("good", "42", "user@example.com", httpUpstream)

			var forwarded []byte
			h.httpUp.handler = func(w http.ResponseWriter, r *http.Request) {
				forwarded, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusOK)
			}

			req := httptest.NewRequest(http.MethodPost, "/mcp/"+httpUpstream, tc.body)
			req.Header.Set("Authorization", "Bearer good")
			resp := h.serve(req)
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if got := h.httpUp.count() != 0; got != tc.reached {
				t.Errorf("transport reached = %v, want %v", got, tc.reached)
			}
			if tc.reached && len(forwarded) != 16 {
				t.Errorf("forwarded %d body bytes, want 16", len(forwarded))
			}
		})
	}
}

func TestServeOverHTTPServer(t *testing.T) {
	h := newHarness(t)
	h.grant("good", "42", "user@example.com", httpUpstream)
	h.httpUp.handler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(SessionHeader, "session-1")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}

	server := httptest.NewServer(h.router)
	t.Cleanup(server.Close)

	req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp/"+httpUpstream, strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer good")
	req.Header.Set("Origin", testOrigin)

	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get(SessionHeader); got != "session-1" {
		t.Errorf("Mcp-Session-Id = %q, want it passed through", got)
	}
}

func TestServerBoundsTheHeaderPhase(t *testing.T) {
	h := newHarness(t)
	server := Server(h.router)

	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{name: "read header timeout", got: server.ReadHeaderTimeout, want: DefaultReadHeaderTimeout},
		{name: "max header bytes", got: server.MaxHeaderBytes, want: DefaultMaxHeaderBytes},
		{name: "idle timeout", got: server.IdleTimeout, want: DefaultIdleTimeout},
		{name: "read timeout left off for streamed requests", got: server.ReadTimeout, want: time.Duration(0)},
		{name: "write timeout left off for sse responses", got: server.WriteTimeout, want: time.Duration(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if diff := cmp.Diff(tc.want, tc.got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}

	t.Run("a client dribbling headers is disconnected", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		// The shipped timeout outlasts a test run, so the assertion is that the
		// field Server sets is the one that severs the connection.
		slow := Server(h.router)
		slow.ReadHeaderTimeout = 50 * time.Millisecond
		go slow.Serve(listener)
		t.Cleanup(func() { slow.Close() })

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("POST /mcp/" + httpUpstream + " HTTP/1.1\r\nHost: tailgate\r\n")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}

		if _, err := io.ReadAll(conn); err != nil {
			t.Fatalf("connection outlived the header timeout: %v", err)
		}
		if h.httpUp.count() != 0 {
			t.Error("a request with incomplete headers reached the transport")
		}
	})
}

func TestShutdownAndCloseReachEveryTransport(t *testing.T) {
	h := newHarness(t)

	if err := h.router.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := h.router.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for name, transport := range map[string]*fakeTransport{httpUpstream: h.httpUp, stdioUpstream: h.stdioUp} {
		if !transport.shutdown {
			t.Errorf("%s was not shut down", name)
		}
		if !transport.closed {
			t.Errorf("%s was not closed", name)
		}
	}
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	urls, err := resource.NewURLs(testFQDN, testPort)
	if err != nil {
		t.Fatalf("NewURLs: %v", err)
	}
	valid := func() Options {
		return Options{
			Upstreams:  []Upstream{{Name: httpUpstream, Transport: newFakeTransport()}},
			Resources:  urls,
			Verifier:   &fakeVerifier{},
			Authorizer: &fakeAuthorizer{},
		}
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*Options)
		wantErr bool
	}{
		{name: "complete options", mutate: func(*Options) {}},
		{name: "missing resource urls", mutate: func(o *Options) { o.Resources = nil }, wantErr: true},
		{name: "missing verifier", mutate: func(o *Options) { o.Verifier = nil }, wantErr: true},
		{name: "missing authorizer", mutate: func(o *Options) { o.Authorizer = nil }, wantErr: true},
		{
			name:    "upstream without a transport",
			mutate:  func(o *Options) { o.Upstreams = []Upstream{{Name: httpUpstream}} },
			wantErr: true,
		},
		{
			name: "duplicate upstream",
			mutate: func(o *Options) {
				o.Upstreams = append(o.Upstreams, Upstream{Name: httpUpstream, Transport: newFakeTransport()})
			},
			wantErr: true,
		},
		{
			name:    "upstream name with a separator",
			mutate:  func(o *Options) { o.Upstreams = []Upstream{{Name: "a/b", Transport: newFakeTransport()}} },
			wantErr: true,
		},
		{
			name:    "empty upstream name",
			mutate:  func(o *Options) { o.Upstreams = []Upstream{{Name: "", Transport: newFakeTransport()}} },
			wantErr: true,
		},
		{
			name:    "relative allowed origin",
			mutate:  func(o *Options) { o.AllowedOrigins = []string{"tailgate.example.ts.net"} },
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := valid()
			tc.mutate(&opts)
			_, err := New(opts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// remoteAddrConn is a connection that reports an address of the test's
// choosing, standing in for a direct connection that never came over Funnel.
type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

// Funnel replaces the connection's RemoteAddr with the relaying tailnet node,
// so an address read from there would charge every internet client to one
// bucket. The client's own address rides on the FunnelConn the TLS listener
// wraps.
func TestClientAddr(t *testing.T) {
	funnelSrc := netip.MustParseAddrPort("203.0.113.7:44321")
	relay := &net.TCPAddr{IP: net.ParseIP("100.64.0.1"), Port: 41641}

	for _, tc := range []struct {
		name string
		conn func(net.Conn) net.Conn
		want netip.Addr
	}{
		{
			name: "funnel connection behind tls",
			conn: func(c net.Conn) net.Conn {
				funnel := &ipn.FunnelConn{Conn: &remoteAddrConn{Conn: c, remote: relay}, Src: funnelSrc}
				return tls.Server(funnel, &tls.Config{})
			},
			want: funnelSrc.Addr(),
		},
		{
			name: "bare funnel connection",
			conn: func(c net.Conn) net.Conn {
				return &ipn.FunnelConn{Conn: &remoteAddrConn{Conn: c, remote: relay}, Src: funnelSrc}
			},
			want: funnelSrc.Addr(),
		},
		{
			name: "direct connection",
			conn: func(c net.Conn) net.Conn {
				return &remoteAddrConn{Conn: c, remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5555}}
			},
			want: netip.MustParseAddr("198.51.100.9"),
		},
		{
			name: "connection with an unparseable address",
			conn: func(c net.Conn) net.Conn { return c },
			want: netip.Addr{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local, remote := net.Pipe()
			t.Cleanup(func() {
				local.Close()
				remote.Close()
			})
			if got := clientAddr(tc.conn(local)); got != tc.want {
				t.Errorf("clientAddr = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServerRecordsTheClientAddress(t *testing.T) {
	want := netip.MustParseAddr("203.0.113.7")
	local, remote := net.Pipe()
	t.Cleanup(func() {
		local.Close()
		remote.Close()
	})
	funnel := &ipn.FunnelConn{Conn: local, Src: netip.AddrPortFrom(want, 44321)}

	server := Server(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	if server.ConnContext == nil {
		t.Fatal("Server built an http.Server that records no client address")
	}
	if got := auth.ClientAddrFrom(server.ConnContext(context.Background(), funnel)); got != want {
		t.Errorf("recorded client address = %v, want %v", got, want)
	}
}
