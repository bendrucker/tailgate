// Package proxy routes authorized requests to MCP upstreams.
package proxy

import (
	"context"
	"errors"
	"io"
)

// Transport is the per-upstream seam between the router and a backing MCP
// server. The HTTP and stdio adapters are independent implementations, selected
// by an upstream's config transport field.
//
// PROVISIONAL. This seam is too thin for streamable HTTP: it opens and closes a
// session but does not carry messages. The real seam must express a POST that
// returns either JSON or an SSE stream, a standalone GET server-to-client
// stream, HTTP DELETE termination, Last-Event-ID resumption, and the split
// where an HTTP upstream mints Mcp-Session-Id while a stdio upstream has none.
// The layer-1.5 spike settles the final shape. See CLAUDE.md.
type Transport interface {
	// Open establishes a new MCP session to the upstream.
	Open(ctx context.Context) (Session, error)
	// Close releases the transport and all of its sessions.
	Close() error
}

// Session carries streamable-HTTP MCP messages in both directions for one
// Mcp-Session-Id.
type Session interface {
	io.Closer
	// ID is the Mcp-Session-Id the client uses to resume the session.
	ID() string
}

var (
	// ErrUnknownUpstream is returned when a route names no configured upstream.
	ErrUnknownUpstream = errors.New("proxy: unknown upstream")
	// ErrCapExceeded is returned when an upstream is at its session cap.
	ErrCapExceeded = errors.New("proxy: upstream session cap exceeded")
)
