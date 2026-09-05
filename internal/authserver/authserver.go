// Package authserver is tailgate's OAuth authorization server.
//
// tailgate issues the tokens its own resources accept. A client identifies
// itself with a Client ID Metadata Document, so there is no client registry
// and no secret: the client is public, proves its request with PKCE, and is
// bound to the redirect URIs its own origin publishes. The person authorizing
// it is identified by the tailnet connection their browser arrives on, which
// tsnet resolves to a user with WhoIs. Nothing here signs, parses, or stores
// a credential beyond the opaque tokens auth.Tokens mints.
//
// # Reaching /authorize
//
// The authorization endpoint answers only a connection that came from a
// tailnet peer. The Funnel listener serves those alongside public traffic, and
// the router marks a Funnel connection so it never carries a peer address:
// its own remote address is the Tailscale ingress relay, and resolving that
// would name the relay as the person. A browser on the public internet gets a
// page saying to open the same URL from a tailnet device. The token endpoint
// and the metadata are public, since the client's backend has no tailnet
// identity and needs none.
//
// # Discovery
//
// The RFC 8414 metadata names tailgate's own origin as the issuer and
// advertises CIMD support, no client authentication, and S256. A client that
// follows RFC 9728 discovery from a 401 and a client that assumes the
// authorization server shares the MCP server's origin both land here.
package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/cimd"
	"github.com/bendrucker/tailgate/internal/resource"
)

// Paths the server serves, all on tailgate's origin.
const (
	// MetadataPath is the RFC 8414 authorization-server metadata location.
	MetadataPath = "/.well-known/oauth-authorization-server"
	// OpenIDMetadataPath is the OpenID Connect discovery location. Clients
	// probe one or the other with no reliable preference, and the document
	// answering both is the same, so serving only one leaves the difference to
	// chance.
	OpenIDMetadataPath = "/.well-known/openid-configuration"
	// AuthorizePath is the authorization endpoint: the consent page on GET,
	// the decision on POST.
	AuthorizePath = "/authorize"
	TokenPath     = "/token"

	// upstreamPathPrefix is where each upstream's resource lives. A client
	// handed a resource URL may look for the authorization-server metadata at
	// the RFC 8414 path-suffixed location under it, which resolves here to
	// the same document.
	upstreamPathPrefix = "/mcp/"

	// maxFormBytes bounds a token or consent request body. Both are a few
	// short form fields.
	maxFormBytes = 64 << 10
)

const (
	// pendingTTL is how long a rendered consent page can be answered.
	pendingTTL = 10 * time.Minute
	// codeTTL is how long an authorization code can be redeemed. RFC 6749
	// section 4.1.2 recommends at most ten minutes.
	codeTTL = 5 * time.Minute
	// redeemedTTL is how long a redeemed code is remembered, so a replay
	// within it revokes what the first redemption issued.
	redeemedTTL = time.Hour

	maxPending  = 1024
	maxCodes    = 4096
	maxRedeemed = 4096
)

// Identify resolves a tailnet peer address to the node and person behind it.
// (*tsnetserver.Server).WhoIs implements it.
type Identify func(ctx context.Context, peer netip.AddrPort) (*apitype.WhoIsResponse, error)

type Options struct {
	// Resources mints the origin every endpoint lives on and the canonical
	// resource URL each upstream's tokens are issued for.
	Resources *resource.URLs
	// HasUpstream reports whether a name is a configured upstream, which a
	// resource parameter must name. It is consulted per request, since the
	// upstream set changes under a configuration reload while the server,
	// which holds every live token, does not.
	HasUpstream func(name string) bool
	// Tokens issues the access and refresh tokens.
	Tokens *auth.Tokens
	// Identify resolves the person behind a tailnet connection.
	Identify Identify
	// Clients resolves client IDs to their metadata documents.
	Clients *cimd.Fetcher
	// Logger receives authorization events. Nil uses slog.Default.
	Logger *slog.Logger
	// Clock drives every lifetime. Nil uses time.Now.
	Clock func() time.Time
}

// Server is the authorization server. It is safe for concurrent use.
type Server struct {
	origin      string
	resources   *resource.URLs
	hasUpstream func(name string) bool
	tokens      *auth.Tokens
	identify    Identify
	clients     *cimd.Fetcher
	logger      *slog.Logger
	now         func() time.Time
	document    []byte

	pending  *table[pendingAuthorization]
	codes    *table[authorizationCode]
	redeemed *table[auth.Issued]
}

// metadata is the RFC 8414 document.
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
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported"`
}

// New builds a Server. It fails on a missing collaborator, since each
// one is what makes an endpoint safe to serve.
func New(opts Options) (*Server, error) {
	switch {
	case opts.Resources == nil:
		return nil, errors.New("authserver: nil resource URLs")
	case opts.Tokens == nil:
		return nil, errors.New("authserver: nil token store")
	case opts.Identify == nil:
		return nil, errors.New("authserver: nil identify")
	case opts.Clients == nil:
		return nil, errors.New("authserver: nil client fetcher")
	case opts.HasUpstream == nil:
		return nil, errors.New("authserver: nil upstream check")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := opts.Clock
	if now == nil {
		now = time.Now
	}

	origin := opts.Resources.Origin()
	document, err := json.Marshal(metadata{
		Issuer:                            origin,
		AuthorizationEndpoint:             origin + AuthorizePath,
		TokenEndpoint:                     origin + TokenPath,
		ScopesSupported:                   resource.SupportedScopes(),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ResourceIndicatorsSupported:       true,
		ClientIDMetadataDocumentSupported: true,
	})
	if err != nil {
		return nil, fmt.Errorf("authserver: encode metadata: %w", err)
	}

	return &Server{
		origin:      origin,
		resources:   opts.Resources,
		hasUpstream: opts.HasUpstream,
		tokens:      opts.Tokens,
		identify:    opts.Identify,
		clients:     opts.Clients,
		logger:      logger,
		now:         now,
		document:    document,
		pending:     newTable[pendingAuthorization](maxPending, pendingTTL, now),
		codes:       newTable[authorizationCode](maxCodes, codeTTL, now),
		redeemed:    newTable[auth.Issued](maxRedeemed, redeemedTTL, now),
	}, nil
}

func (s *Server) Handles(path string) bool {
	switch path {
	case AuthorizePath, TokenPath, MetadataPath, OpenIDMetadataPath:
		return true
	}
	for _, prefix := range []string{MetadataPath, OpenIDMetadataPath} {
		if name, ok := strings.CutPrefix(path, prefix+upstreamPathPrefix); ok && s.hasUpstream(name) {
			return true
		}
	}
	return false
}

// ServeHTTP dispatches by path. A path whose escaped form differs from its
// decoded one is refused, since Handles matched on the decoded form and the
// two must agree for the match to mean anything.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.EscapedPath() != r.URL.Path {
		http.NotFound(w, r)
		return
	}
	switch r.URL.Path {
	case AuthorizePath:
		s.serveAuthorize(w, r)
	case TokenPath:
		s.serveToken(w, r)
	default:
		if s.Handles(r.URL.Path) {
			s.serveMetadata(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (s *Server) serveMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(s.document)))
	w.Write(s.document)
}

// upstreamFor maps a resource parameter to the upstream it names. The prefix
// cut only picks the candidate: the check is the exact comparison against
// that upstream's canonical resource URL, since every resource string the
// system issues comes from resource.URLs and nothing is normalized here.
func (s *Server) upstreamFor(resourceURL string) (string, bool) {
	name, ok := strings.CutPrefix(resourceURL, s.origin+upstreamPathPrefix)
	if !ok || !s.hasUpstream(name) || s.resources.ResourceURL(name) != resourceURL {
		return "", false
	}
	return name, true
}

// writeOAuthError answers with the RFC 6749 section 5.2 error object.
func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	payload, err := json.Marshal(struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}{Error: code, Description: description})
	if err != nil {
		s.logger.Error("encoding oauth error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	noStore(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	w.Write(payload)
}

// noStore marks a response that carries a token, a code, or a consent form
// as uncacheable, per RFC 6749 section 5.1.
func noStore(h http.Header) {
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
