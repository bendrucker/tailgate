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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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

// maxTokenRequestBytes bounds a proxied token request. An OAuth token request
// is a short form body, and the bound is what keeps an unauthenticated caller
// from spending tailgate's memory on a path that reaches tsidp.
const maxTokenRequestBytes = 64 << 10

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
	document  []byte
	authorize *url.URL
	token     *url.URL
	client    *http.Client
	logger    *slog.Logger
}

// New builds the facade for an origin whose tokens are issued by issuer.
//
// client must dial the tailnet, the same requirement introspection has: the
// token endpoint is reached as tailgate's node rather than over the public
// internet.
func New(origin, issuer string, client *http.Client, logger *slog.Logger) (*Facade, error) {
	if client == nil {
		return nil, errors.New("authserver: nil HTTP client")
	}
	if logger == nil {
		return nil, errors.New("authserver: nil logger")
	}
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

	return &Facade{
		document:  document,
		authorize: upstream.JoinPath(AuthorizePath),
		token:     upstream.JoinPath(TokenPath),
		client:    client,
		logger:    logger,
	}, nil
}

// Handles reports whether the facade owns a path, so the router can dispatch
// without duplicating the path set.
func (f *Facade) Handles(path string) bool {
	switch path {
	case MetadataPath, OpenIDMetadataPath, AuthorizePath, TokenPath:
		return true
	}
	// RFC 8414 section 3.1 also locates metadata by inserting the well-known
	// prefix ahead of the issuer's path, which is what a client probes when it
	// treats /mcp/<name> as the issuer.
	return strings.HasPrefix(path, MetadataPath+"/")
}

// ServeHTTP dispatches to the endpoint owning the request path. Every endpoint
// here is unauthenticated, which is inherent to OAuth discovery and to the
// token exchange that has no token yet.
func (f *Facade) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == AuthorizePath:
		f.serveAuthorize(w, r)
	case r.URL.Path == TokenPath:
		f.serveToken(w, r)
	case f.Handles(r.URL.Path):
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
	// Discovery is fetched cross-origin by browser-based clients, and the
	// document is public by definition.
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenRequestBytes))
	if err != nil {
		http.Error(w, "invalid token request", http.StatusBadRequest)
		return
	}

	proxied, err := http.NewRequestWithContext(r.Context(), http.MethodPost, f.token.String(), strings.NewReader(string(body)))
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
