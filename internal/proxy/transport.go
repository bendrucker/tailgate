// Package proxy routes authorized requests to MCP upstreams.
//
// # Seam
//
// A Transport serves one upstream's MCP endpoint over streamable HTTP. The
// seam is HTTP itself. Expressing the transport as a handler carries every
// protocol obligation without re-encoding it in a bespoke interface, and it is
// what lets one seam span revisions that disagree about the shape of a
// session: a POST answered with a single JSON object or an SSE stream, plus
// whichever of Mcp-Session-Id, DELETE termination, the standalone GET stream,
// and Last-Event-ID resumption the revision in use still has.
//
// The HTTP adapter reverse-proxies and preserves the upstream's session and
// SSE bytes verbatim, so it carries any revision the upstream itself speaks.
// The stdio adapter implements the server side of streamable HTTP over a child
// process, correlating JSON-RPC messages itself and supplying whatever the
// revision expects of a server that the child has no notion of.
//
// # Error taxonomy
//
// The sentinel errors below are the shared vocabulary for proxy-side
// request-path failures. Handlers translate them with StatusOf so every
// layer-2 unit maps the same condition to the same status code. Auth failures
// are the router's to map, because they carry response content a status alone
// cannot: auth.ErrInvalidToken becomes 401 with a WWW-Authenticate challenge,
// and auth.ErrUnavailable becomes 503.
//
// # Lifecycle
//
// Construction never dials: a Transport that cannot reach its upstream reports
// it per-request, so a broken upstream degrades to ErrUpstreamUnavailable
// rather than blocking startup. Shutdown drains: the transport refuses new
// work with 503, lets in-flight requests and open SSE streams finish, and
// returns when they have or when ctx expires. Close tears down immediately and
// is safe after Shutdown. The server stops the Funnel listener first, then
// shuts down transports with a drain deadline, then closes the tsnet node.
package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
)

// Transport serves one upstream's MCP endpoint.
//
// ServeHTTP receives requests already authorized and rewritten by the router:
// the URL path is the endpoint root ("/"), the Authorization header and
// inbound X-Forwarded-* headers are stripped, and the request context carries
// the caller's auth.Identity. A Transport never sees an unauthenticated
// request; anything reaching it may spawn work on the upstream.
//
// Timeout policy lives here, not on the server: only the transport knows
// whether a response is a bounded JSON body or an SSE stream that must stay
// open, so blanket server write timeouts are wrong. Servers set
// ReadHeaderTimeout; transports bound everything after the headers.
type Transport interface {
	http.Handler
	// Shutdown drains the transport: refuse new requests, then wait for
	// in-flight requests and streams to finish or ctx to expire.
	Shutdown(ctx context.Context) error
	// Closer tears down immediately, abandoning in-flight work.
	io.Closer
}

var (
	// ErrUnknownUpstream is returned when a route names no configured upstream.
	ErrUnknownUpstream = errors.New("proxy: unknown upstream")
	// ErrSessionNotFound is returned for an Mcp-Session-Id that is expired or
	// was never issued. The 404 mapping is load-bearing: it is what tells an
	// MCP client to discard the session and re-initialize.
	ErrSessionNotFound = errors.New("proxy: session not found")
	// ErrCapExceeded is returned when the caller is at their session cap for
	// an upstream.
	ErrCapExceeded = errors.New("proxy: session cap exceeded")
	// ErrUpstreamUnavailable is returned when the upstream cannot be reached
	// or fails before producing a response.
	ErrUpstreamUnavailable = errors.New("proxy: upstream unavailable")
	// ErrUpstreamTimeout is returned when a non-SSE exchange exceeds the
	// transport's deadline.
	ErrUpstreamTimeout = errors.New("proxy: upstream timeout")
	// ErrDraining is returned for requests arriving after shutdown began.
	ErrDraining = errors.New("proxy: draining")
)

// StatusOf maps a request-path error to the HTTP status its handler writes.
// Unrecognized errors map to 500: an unclassified failure is a server fault
// and must never pass through as success.
func StatusOf(err error) int {
	switch {
	case errors.Is(err, ErrUnknownUpstream):
		return http.StatusNotFound
	case errors.Is(err, ErrSessionNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrCapExceeded):
		return http.StatusTooManyRequests
	case errors.Is(err, ErrUpstreamUnavailable):
		return http.StatusBadGateway
	case errors.Is(err, ErrUpstreamTimeout):
		return http.StatusGatewayTimeout
	case errors.Is(err, ErrDraining):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
