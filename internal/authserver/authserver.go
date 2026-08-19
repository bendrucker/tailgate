// Package authserver presents the authorization server's endpoints at
// tailgate's own origin.
//
// tailgate is a resource server, and the correct discovery path does not need
// this package: an unauthenticated request gets a 401 naming the RFC 9728
// metadata document, that document names tsidp as the authorization server,
// and the client goes there for tokens. Claude Code follows exactly that path.
//
// Some clients never read the document. They assume the authorization server
// shares the MCP server's origin and send /authorize and /token to tailgate,
// which answers 404 because neither path routes to an upstream. claude.ai does
// this: it sent a browser to tailgate's /authorize carrying a correct client_id
// and PKCE challenge, having made no prior request to tailgate at all. Its
// connector form offers no field for an authorization endpoint, so nothing on
// that side can redirect it.
//
// The facade meets those clients where they look. Everything it advertises
// lives on tailgate's origin, so a client that discovers and a client that
// assumes reach the same two endpoints, and tailgate forwards each to tsidp.
//
// # What is forwarded, and how
//
// /authorize is a redirect rather than a proxy. tsidp identifies the person
// authorizing by the tailnet identity of the connection, so proxying the
// browser through tailgate would present tailgate's node identity instead of
// theirs and mint a token for the wrong subject. The redirect keeps the browser
// talking to tsidp directly. tsidp refuses /authorize over Funnel, so the
// browser completing this leg must be on the tailnet.
//
// /token is a proxy, because the caller is the client's backend rather than a
// browser and it has no tailnet identity to preserve. tsidp authenticates it by
// client credentials, which pass through untouched, as does the RFC 8707
// resource parameter that decides the token's audience.
//
// # Why /register is absent
//
// Dynamic client registration is deliberately not fronted, and the reason is
// not that no client wants it. tsidp resolves the tsidp app capability from the
// caller's tailnet identity, and only three of its handlers consult it:
// /register, /clients/, and the admin UI. Proxying /register would make that
// call arrive as tailgate's node, so tailgate would need allow_dcr in the
// tailnet policy. Nothing else it does needs any capability at all:
// introspection and the token endpoint have no such check.
//
// Granting it would tie tailgate's ability to serve to a policy rule matching
// its node identity, which holds only while the node is untagged and owned by
// the same user the rule names. Tagging the node later would break the facade
// with a 403 that names a capability rather than a tag. Leaving /register out
// keeps tailgate needing no capability, so its node identity can change freely.
//
// The cost is that a client must be registered out of band and its id and
// secret configured. That is one setup step against a standing policy coupling,
// and the client that motivated this package requires manual credentials
// anyway.
package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Paths the facade serves, all on tailgate's origin.
const (
	// MetadataPath is the RFC 8414 authorization-server metadata location.
	MetadataPath = "/.well-known/oauth-authorization-server"
	// OpenIDMetadataPath is the OpenID Connect discovery location. Clients
	// probe one or the other with no reliable preference, and the document
	// answering both is the same, so serving only one leaves the difference to
	// chance.
	OpenIDMetadataPath = "/.well-known/openid-configuration"
	// AuthorizePath redirects to the issuer's authorization endpoint.
	AuthorizePath = "/authorize"
	// TokenPath proxies to the issuer's token endpoint.
	TokenPath = "/token"
)

// upstreamPathPrefix is the prefix every upstream is addressed under, and the
// path a client that mistakes an upstream's resource URI for an issuer
// identifier inserts the well-known prefix ahead of.
const upstreamPathPrefix = "/mcp/"

// maxTokenRequestBytes bounds a proxied token request. An OAuth token request
// is a short form body, and the bound is what keeps an unauthenticated caller
// from spending tailgate's memory on a path that reaches tsidp.
const maxTokenRequestBytes = 64 << 10

// defaultTokenExchangeTimeout bounds both halves of a proxied token exchange.
// The server sets no ReadTimeout, since an MCP response may be an SSE stream
// held open, so an unauthenticated caller dribbling a body would otherwise
// hold a connection for as long as it liked.
const defaultTokenExchangeTimeout = 10 * time.Second

// metadata is the RFC 8414 document. Both endpoints name tailgate rather than
// the issuer, so a client that reads this document and a client that assumes
// the origin converge on the same requests.
type metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ResourceIndicatorsSupported       bool     `json:"resource_indicators_supported"`
}

// Advertised capabilities. Each is what tsidp actually implements, narrowed to
// what tailgate is willing to front: the authorization-code and refresh flows,
// PKCE with S256, and RFC 8707 resource indicators, which tailgate's audience
// check requires the client to use.
var (
	scopesSupported                   = []string{"openid", "email"}
	responseTypesSupported            = []string{"code"}
	grantTypesSupported               = []string{"authorization_code", "refresh_token"}
	tokenEndpointAuthMethodsSupported = []string{"client_secret_basic", "client_secret_post"}
	codeChallengeMethodsSupported     = []string{"S256"}
)

// Facade serves the authorization-server surface at tailgate's origin. It is
// safe for concurrent use.
type Facade struct {
	// metadata is the exact set of paths serving the document, so a probe for
	// an upstream that is not configured is answered as the absence it is.
	metadata  map[string]bool
	document  []byte
	authorize *url.URL
	token     *url.URL
	client    *http.Client
	timeout   time.Duration
	logger    *slog.Logger
}

// New builds the facade for an origin whose tokens are issued by issuer.
//
// upstreams names the configured upstreams, which is what decides the RFC 8414
// section 3.1 paths the facade answers. It must be the same list the metadata
// handler is built from, so a client cannot discover an authorization server
// for a resource that has none.
//
// client must dial the tailnet, the same requirement introspection has: the
// token endpoint is reached as tailgate's node rather than over the public
// internet.
func New(origin, issuer string, upstreams []string, client *http.Client, logger *slog.Logger) (*Facade, error) {
	if client == nil {
		return nil, errors.New("authserver: nil HTTP client")
	}
	if logger == nil {
		return nil, errors.New("authserver: nil logger")
	}
	// The redirect policy is set on a copy, since the client belongs to the
	// caller. A redirect followed here would be fetched from inside the tailnet
	// on behalf of an unauthenticated caller, and its body returned to them.
	direct := *client
	direct.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	base, err := absoluteURL("origin", origin)
	if err != nil {
		return nil, err
	}
	upstream, err := absoluteURL("issuer", issuer)
	if err != nil {
		return nil, err
	}

	document, err := json.Marshal(metadata{
		Issuer:                            strings.TrimSuffix(base.String(), "/"),
		AuthorizationEndpoint:             base.JoinPath(AuthorizePath).String(),
		TokenEndpoint:                     base.JoinPath(TokenPath).String(),
		ScopesSupported:                   scopesSupported,
		ResponseTypesSupported:            responseTypesSupported,
		GrantTypesSupported:               grantTypesSupported,
		TokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:     codeChallengeMethodsSupported,
		ResourceIndicatorsSupported:       true,
	})
	if err != nil {
		return nil, fmt.Errorf("authserver: encode metadata: %w", err)
	}

	metadata := map[string]bool{MetadataPath: true, OpenIDMetadataPath: true}
	for _, name := range upstreams {
		metadata[MetadataPath+upstreamPathPrefix+name] = true
	}

	return &Facade{
		metadata:  metadata,
		document:  document,
		authorize: upstream.JoinPath(AuthorizePath),
		token:     upstream.JoinPath(TokenPath),
		client:    &direct,
		timeout:   defaultTokenExchangeTimeout,
		logger:    logger,
	}, nil
}

// Handles reports whether the facade owns a path, so the router can dispatch
// without duplicating the path set. A path it does not own falls through to
// the router, which answers it as unrouted.
func (f *Facade) Handles(path string) bool {
	return path == AuthorizePath || path == TokenPath || f.metadata[path]
}

// ServeHTTP dispatches to the endpoint owning the request path. Every endpoint
// here is unauthenticated, which is inherent to OAuth discovery and to the
// token exchange that has no token yet.
func (f *Facade) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The paths are matched decoded, so a percent-encoded spelling would reach
	// an endpoint under a name the router never resolved.
	if r.URL.EscapedPath() != r.URL.Path {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.URL.Path == AuthorizePath:
		f.serveAuthorize(w, r)
	case r.URL.Path == TokenPath:
		f.serveToken(w, r)
	case f.metadata[r.URL.Path]:
		f.serveMetadata(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *Facade) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(f.document)))
	w.Write(f.document)
}

// serveAuthorize sends the browser to the issuer, preserving the query
// verbatim. Every parameter that decides what is authorized lives there:
// client_id, redirect_uri, state, and the PKCE challenge. Rewriting any of them
// would change what the person is consenting to, and validating them is the
// issuer's job, so the query crosses untouched.
func (f *Facade) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	target := *f.authorize
	target.RawQuery = r.URL.RawQuery
	// The query carries the client's state and PKCE challenge, so the log names
	// only the endpoint the browser is being sent to.
	endpoint := *f.authorize
	endpoint.RawQuery = ""
	f.logger.Info("redirecting authorization request", "to", endpoint.String())
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// serveToken forwards the token request to the issuer and returns its answer.
//
// Client credentials and the resource parameter pass through as the client sent
// them, so the token tsidp mints carries the audience tailgate's verifier will
// later require. Only hop-by-hop and identity-bearing headers are dropped.
func (f *Facade) serveToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// An h2 connection has no deadline to set, and the exchange below is
	// bounded either way, so an unsupported controller is not a refusal.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(f.timeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		f.logger.Error("setting token request deadline", "err", err)
		http.Error(w, "token endpoint unavailable", http.StatusBadGateway)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenRequestBytes))
	if err != nil {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}
	if !hasClientCredentials(r.Header, body) {
		// The log names the refusal, never the request: the body it was read
		// from is where a client secret lives.
		f.logger.Warn("refusing token request that presents no client credentials")
		f.writeOAuthError(w, http.StatusBadRequest, "invalid_client", "client authentication is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), f.timeout)
	defer cancel()

	proxied, err := http.NewRequestWithContext(ctx, http.MethodPost, f.token.String(), strings.NewReader(string(body)))
	if err != nil {
		f.logger.Error("building token request", "err", err)
		http.Error(w, "token endpoint unavailable", http.StatusBadGateway)
		return
	}
	// The client authenticates itself to the issuer, not to tailgate. These are
	// the only headers that carry that, plus the content type describing the
	// form the credentials may also live in.
	for _, header := range []string{"Authorization", "Content-Type", "Accept"} {
		if value := r.Header.Get(header); value != "" {
			proxied.Header.Set(header, value)
		}
	}

	response, err := f.client.Do(proxied)
	if err != nil {
		f.logger.Error("proxying token request", "err", err)
		http.Error(w, "token endpoint unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()

	// A token response is a small JSON document, and the same bound applies in
	// both directions so a misbehaving issuer cannot be the way memory is spent.
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxTokenRequestBytes))
	if err != nil {
		f.logger.Error("reading token response", "err", err)
		http.Error(w, "token endpoint unavailable", http.StatusBadGateway)
		return
	}

	if contentType := response.Header.Get("Content-Type"); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	// An OAuth error carries its detail in the body, and the client can only act
	// on what the issuer said, so the status and payload cross unchanged.
	f.logger.Info("proxied token request", "status", response.StatusCode)
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(response.StatusCode)
	w.Write(payload)
}

// hasClientCredentials reports whether the request presents client
// authentication in one of the two forms the facade advertises.
//
// tailgate cannot check the credentials, only that some were offered, and that
// is the point. The request reaches tsidp over tsnet, so it arrives carrying
// tailgate's own tailnet node identity. tsidp identifies a caller by
// credentials first and by that node identity last, so forwarding a request
// with none would let an anonymous caller off the internet be identified as
// tailgate's node. Whether the token endpoint actually consults that fallback
// decides how bad it is, not whether the facade should be the thing that sets
// it up.
func hasClientCredentials(header http.Header, body []byte) bool {
	scheme, credential, ok := strings.Cut(header.Get("Authorization"), " ")
	if ok && strings.EqualFold(scheme, "Basic") && strings.TrimSpace(credential) != "" {
		return true
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return false
	}
	return form.Get("client_id") != "" && form.Get("client_secret") != ""
}

// writeOAuthError answers with the RFC 6749 section 5.2 error object. The
// status is 400 rather than 401: that section makes 401 mandatory only for a
// caller whose Authorization header was rejected, and a 401 here would assert
// that the caller must authenticate to tailgate. It never does. The credentials
// authenticate the client to the issuer, and tailgate only checks that they are
// present.
func (f *Facade) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	payload, err := json.Marshal(struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{Error: code, Description: description})
	if err != nil {
		f.logger.Error("encoding oauth error", "err", err)
		http.Error(w, "token endpoint unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	w.Write(payload)
}

// absoluteURL parses one of the two URLs the facade is built from, rejecting
// anything that would put a path, query, or fragment in front of the endpoints
// derived from it.
func absoluteURL(field, raw string) (*url.URL, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("authserver: parse %s %q: %w", field, raw, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("authserver: %s %q must be an http or https URL", field, raw)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("authserver: %s %q has no host", field, raw)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("authserver: %s %q must have no query or fragment", field, raw)
	}
	return parsed, nil
}
