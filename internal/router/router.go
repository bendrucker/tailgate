// Package router is tailgate's internet-facing HTTP handler.
//
// # Pipeline
//
// Every request runs the same sequence, and each step must pass before the
// next observes anything: recover, Origin validation, routing, token
// extraction, verification, authorization, session binding, body limiting, and
// finally dispatch to the upstream's proxy.Transport. Authorization precedes
// dispatch unconditionally, so a Transport never sees an unauthenticated
// request and never spawns work for one.
//
// # Routing
//
// Upstreams are addressed at /mcp/<name>, matched as exact membership in the
// configured set. The path is rejected outright if it carries percent-encoding
// or is not already clean, so /mcp//x, /mcp/x/../y, and /mcp/%2e%2e/y resolve
// to nothing rather than aliasing an upstream. The RFC 9728 well-known subtree
// routes to the metadata handler and can never reach an upstream.
//
// # Server settings
//
// The router bounds request bodies, and transports bound everything after the
// response headers. The header phase belongs to the http.Server, because the
// handler only runs once the headers are read, so [Server] builds one with
// those limits already applied.
package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/proxy"
	"github.com/bendrucker/tailgate/internal/resource"
)

const (
	// PathPrefix is the path prefix every upstream is addressed under.
	PathPrefix = "/mcp/"
	// SessionHeader carries the MCP session identifier in both directions.
	SessionHeader = "Mcp-Session-Id"
	// IdentityHeaderPrefix is proxy.IdentityHeaderPrefix, the prefix reserved
	// for headers tailgate sets about the caller.
	IdentityHeaderPrefix = proxy.IdentityHeaderPrefix
)

// Defaults applied when Options leaves the corresponding field zero.
const (
	// DefaultMaxBodyBytes bounds a request body. An MCP client request is a
	// single JSON-RPC message, so a megabyte is generous.
	DefaultMaxBodyBytes = 1 << 20
	// DefaultMaxSessions bounds the session-binding table.
	DefaultMaxSessions = 4096
	// DefaultSessionTTL expires a binding whose session has gone quiet. It is
	// well past any live MCP session's idle period, because expiry retires the
	// session: the holder's next request is refused and it must re-initialize.
	DefaultSessionTTL = time.Hour
)

// Header-phase limits [Server] applies. They bound what a caller can spend
// before any handler runs, which is the one window no router or transport
// control covers.
const (
	// DefaultReadHeaderTimeout bounds the header phase against a client that
	// dribbles headers to hold a connection open.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultMaxHeaderBytes bounds the request line and headers together, so an
	// unauthenticated caller cannot spend more than this on a request target
	// that routes nowhere.
	DefaultMaxHeaderBytes = 64 << 10
	// DefaultIdleTimeout reclaims a kept-alive connection between requests. It
	// never applies to a request in flight, so an SSE stream is unaffected.
	DefaultIdleTimeout = 2 * time.Minute
)

// Reasons recorded on the audit log for refusals the router makes itself,
// ahead of or alongside the policy decision.
const (
	ReasonNoToken                = "no bearer token presented"
	ReasonMalformedAuthorization = "malformed Authorization header"
	ReasonInvalidToken           = "token rejected by the issuer"
	ReasonVerifierUnavailable    = "token verification unavailable"
	ReasonOriginNotAllowed       = "origin not allowed"
	ReasonSessionBound           = "session bound to a different identity"
)

// Verifier validates a bearer token against an upstream's canonical resource
// URI. *auth.Verifier implements it.
type Verifier interface {
	Verify(ctx context.Context, token, resource string) (auth.Identity, error)
}

// Authorizer evaluates policy for a verified identity. *auth.Authorizer
// implements it.
type Authorizer interface {
	Authorize(id auth.Identity, upstream string) auth.Decision
}

// Upstream is one routable MCP upstream.
type Upstream struct {
	// Name is the single path segment addressing the upstream at /mcp/<name>.
	// It is also the name resource.URLs canonicalizes into the audience the
	// token must carry.
	Name string
	// Transport serves the upstream once the request is authorized.
	Transport proxy.Transport
	// TransportManagesSessions waives the router's binding of Mcp-Session-Id to
	// the authenticated identity. Set it only for a transport that mints and
	// binds its own sessions, which is stdiotransport. Left false, the router
	// binds, so an upstream wired without a considered answer gets the
	// protection rather than losing it silently.
	TransportManagesSessions bool
}

// Options configures a Router. Every collaborator is injected: the router
// reads no global state and registers nothing.
type Options struct {
	// Upstreams is the routable set. A name outside it is a 404.
	Upstreams []Upstream
	// Resources mints each upstream's canonical resource URI and the
	// WWW-Authenticate challenge pointing at its metadata document.
	Resources *resource.URLs
	// Metadata serves the RFC 9728 well-known subtree. A nil handler answers
	// 404 there, which breaks discovery but never routes to an upstream.
	Metadata http.Handler
	// Verifier and Authorizer gate every upstream request.
	Verifier   Verifier
	Authorizer Authorizer
	// Audit records every authorization decision. A nil Logger writes to
	// slog.Default rather than dropping decisions.
	Audit *audit.Logger
	// AllowedOrigins is the set of browser origins permitted to reach tailgate,
	// normally just the canonical Funnel origin. An empty set refuses every
	// request that carries an Origin header; requests without one, which is
	// every non-browser MCP client, are unaffected.
	AllowedOrigins []string
	// MaxBodyBytes bounds a request body. Zero or less uses
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// MaxSessions bounds the session-binding table. Zero or less uses
	// DefaultMaxSessions.
	MaxSessions int
	// SessionTTL expires an idle binding. Zero or less uses DefaultSessionTTL.
	SessionTTL time.Duration
	// Logger receives request-path events that are not authorization
	// decisions. Nil uses slog.Default.
	Logger *slog.Logger
	// Clock drives session-binding expiry. Nil uses time.Now.
	Clock func() time.Time
}

// Router serves the public surface: discovery metadata, and authorized,
// credential-stripped requests to each upstream's transport.
type Router struct {
	upstreams  map[string]*upstream
	resources  *resource.URLs
	metadata   http.Handler
	verifier   Verifier
	authorizer Authorizer
	audit      *audit.Logger
	origins    map[string]bool
	maxBody    int64
	sessions   *sessionBindings
	logger     *slog.Logger
}

// upstream is one configured route with its precomputed audience.
type upstream struct {
	name         string
	transport    proxy.Transport
	bindSessions bool
	resourceURL  string
}

// New builds a Router from opts. It fails on a missing collaborator rather
// than degrading: a router without a verifier or an audience source could only
// serve requests it cannot authenticate.
//
// Serve the result with [Server]. The router runs after the request headers
// are read, so nothing here defends against a client that dribbles them.
func New(opts Options) (*Router, error) {
	if opts.Resources == nil {
		return nil, fmt.Errorf("router: nil resource URLs")
	}
	if opts.Verifier == nil {
		return nil, fmt.Errorf("router: nil verifier")
	}
	if opts.Authorizer == nil {
		return nil, fmt.Errorf("router: nil authorizer")
	}

	upstreams := make(map[string]*upstream, len(opts.Upstreams))
	for _, u := range opts.Upstreams {
		if err := resource.ValidateName(u.Name); err != nil {
			return nil, err
		}
		if u.Transport == nil {
			return nil, fmt.Errorf("router: upstream %q has no transport", u.Name)
		}
		if _, ok := upstreams[u.Name]; ok {
			return nil, fmt.Errorf("router: duplicate upstream %q", u.Name)
		}
		upstreams[u.Name] = &upstream{
			name:         u.Name,
			transport:    u.Transport,
			bindSessions: !u.TransportManagesSessions,
			resourceURL:  opts.Resources.ResourceURL(u.Name),
		}
	}

	origins := make(map[string]bool, len(opts.AllowedOrigins))
	for _, origin := range opts.AllowedOrigins {
		normalized := normalizeOrigin(strings.TrimSuffix(strings.TrimSpace(origin), "/"))
		if normalized == "" {
			return nil, fmt.Errorf("router: allowed origin %q is not an absolute origin", origin)
		}
		origins[normalized] = true
	}

	maxBody := opts.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Router{
		upstreams:  upstreams,
		resources:  opts.Resources,
		metadata:   opts.Metadata,
		verifier:   opts.Verifier,
		authorizer: opts.Authorizer,
		audit:      opts.Audit,
		origins:    origins,
		maxBody:    maxBody,
		sessions:   newSessionBindings(opts.MaxSessions, opts.SessionTTL, opts.Clock),
		logger:     logger,
	}, nil
}

// Server returns an http.Server serving h with the header-phase limits every
// internet-facing tailgate listener needs. It exists so wiring a listener
// cannot omit them: a zero-valued http.Server reads headers with no deadline
// and no useful size bound, and a client that dribbles them holds a connection
// without ever reaching the handler's defenses.
//
// ReadTimeout and WriteTimeout stay zero deliberately. An MCP response may be
// an SSE stream held open for the life of a session, so a whole-request
// deadline would sever it. Each transport bounds its own exchange instead.
func Server(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: DefaultReadHeaderTimeout,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
		IdleTimeout:       DefaultIdleTimeout,
	}
}

// ServeHTTP runs the request pipeline. The panic recovery is outermost, so a
// panic anywhere below it becomes a 500 and never reaches an upstream.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := newResponseRecorder(w)
	defer rt.recoverPanic(rec, r)
	rt.route(rec, r)
}

// Shutdown drains every upstream transport concurrently and returns the first
// error, or ctx's error if the drain deadline passes first.
func (rt *Router) Shutdown(ctx context.Context) error {
	errs := make(chan error, len(rt.upstreams))
	for _, up := range rt.upstreams {
		go func() { errs <- up.transport.Shutdown(ctx) }()
	}
	var err error
	for range rt.upstreams {
		err = errors.Join(err, <-errs)
	}
	return err
}

// Close tears down every upstream transport, abandoning in-flight work.
func (rt *Router) Close() error {
	var err error
	for _, up := range rt.upstreams {
		err = errors.Join(err, up.transport.Close())
	}
	return err
}

func (rt *Router) route(rec *responseRecorder, r *http.Request) {
	name, routed := upstreamName(r.URL)
	up, ok := rt.upstreams[name]

	if !rt.originAllowed(r) {
		// The audit record names an upstream only once the path resolved to a
		// configured one. The segment is caller-supplied, so auditing it
		// unresolved would let an unauthenticated client write arbitrary values
		// into the decision log.
		refused := ""
		if ok {
			refused = up.name
		}
		rt.audit.Deny(r.Context(), auth.Identity{}, refused, ReasonOriginNotAllowed)
		http.Error(rec, "forbidden origin", http.StatusForbidden)
		return
	}

	if isMetadataPath(r.URL) {
		if rt.metadata == nil {
			http.NotFound(rec, r)
			return
		}
		rt.metadata.ServeHTTP(rec, r)
		return
	}

	if !routed || !ok {
		// Unrouted requests are the internet's background noise, so they are
		// not audit decisions: nothing was authorized or refused.
		rt.logger.Debug("no route", "method", r.Method, "path", r.URL.EscapedPath())
		http.Error(rec, "not found", proxy.StatusOf(proxy.ErrUnknownUpstream))
		return
	}
	rt.serveUpstream(rec, r, up)
}

func (rt *Router) serveUpstream(rec *responseRecorder, r *http.Request, up *upstream) {
	id, ok := rt.authenticate(rec, r, up)
	if !ok {
		return
	}

	decision := rt.authorizer.Authorize(id, up.name)
	rt.audit.Record(r.Context(), decision)
	if !decision.Allow {
		http.Error(rec, "forbidden", http.StatusForbidden)
		return
	}

	release, ok := rt.claimSession(rec, r, up, id)
	if !ok {
		return
	}
	defer release()
	if !rt.limitBody(rec, r) {
		return
	}
	rt.dispatch(rec, r, up, id)
}

// dispatch hands the request to the transport with the caller's credentials
// removed and their identity moved into the context, which is the only channel
// an upstream can trust.
func (rt *Router) dispatch(rec *responseRecorder, r *http.Request, up *upstream, id auth.Identity) {
	if up.bindSessions {
		rec.onHeader = func(status int, header http.Header) {
			rt.recordSession(r, up, id, status, header)
		}
	}

	outbound := r.Clone(auth.WithIdentity(r.Context(), id))
	proxy.StripCredentials(outbound.Header)
	outbound.URL.Path = "/"
	outbound.URL.RawPath = ""

	up.transport.ServeHTTP(rec, outbound)
}

// isMetadataPath reports whether the request addresses the RFC 9728 well-known
// subtree. The metadata handler re-matches the full path itself, so the whole
// subtree is routed to it and nothing under it can fall through to an upstream.
func isMetadataPath(u *url.URL) bool {
	return u.Path == resource.MetadataPathPrefix || strings.HasPrefix(u.Path, resource.MetadataPathPrefix+"/")
}

// upstreamName extracts the upstream name from an upstream request path. The
// path must already be clean and free of percent-encoding: an encoded or
// traversable path is rejected rather than normalized, so no two request
// targets can ever resolve to one upstream.
func upstreamName(u *url.URL) (string, bool) {
	if u.EscapedPath() != u.Path {
		return "", false
	}
	if u.Path != path.Clean(u.Path) {
		return "", false
	}
	name, ok := strings.CutPrefix(u.Path, PathPrefix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}

var _ http.Handler = (*Router)(nil)
