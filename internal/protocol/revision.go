// Package protocol models the MCP protocol revisions tailgate speaks and the
// per-request metadata each one puts on the wire.
//
// tailgate fronts MCP servers it does not control for clients it does not
// control, so it speaks more than one revision at once and decides per request
// which one applies. The revision is what selects the rules downstream: whether
// a session header means anything, whether HTTP headers mirror the request
// body, and whether an initialize handshake precedes any work.
//
// # Eras
//
// Revisions 2025-03-26 through 2025-11-25 are stateful: the client opens with
// initialize, the server mints an Mcp-Session-Id, and every later request
// carries it. Revision 2026-07-28 removed both. Each request stands alone,
// carrying its own protocol version and client capabilities in the body's
// _meta, and mirroring selected body fields into HTTP headers so an
// intermediary can route and inspect without parsing the body. tailgate is
// exactly that intermediary, which is why [ValidateMirrored] lives here.
package protocol

import (
	"errors"
	"fmt"
)

// Revision is an MCP protocol revision, spelled as the dated string that
// appears in the MCP-Protocol-Version header.
//
// Revisions are dated, so lexical order is chronological order and a revision
// range is an ordinary string comparison.
type Revision string

// The revisions tailgate recognizes.
const (
	Rev20241105 Revision = "2024-11-05"
	Rev20250326 Revision = "2025-03-26"
	Rev20250618 Revision = "2025-06-18"
	Rev20251125 Revision = "2025-11-25"
	Rev20260728 Revision = "2026-07-28"
)

// Assumed is the revision a request without an MCP-Protocol-Version header is
// treated as speaking. The header was introduced in 2025-06-18, so its absence
// means the client predates it.
const Assumed = Rev20250326

// ErrUnsupportedRevision rejects a version tailgate does not recognize.
// Proxying it would hand an upstream a dialect neither end agreed to.
var ErrUnsupportedRevision = errors.New("protocol: unsupported MCP revision")

var supported = map[Revision]bool{
	Rev20241105: true,
	Rev20250326: true,
	Rev20250618: true,
	Rev20251125: true,
	Rev20260728: true,
}

// Supported lists the recognized revisions oldest first. It is the set an
// UnsupportedProtocolVersionError reports back to a client.
var Supported = []Revision{Rev20241105, Rev20250326, Rev20250618, Rev20251125, Rev20260728}

// Parse resolves an MCP-Protocol-Version header value. An empty value is
// [Assumed]; anything unrecognized is an error rather than a passthrough.
func Parse(value string) (Revision, error) {
	if value == "" {
		return Assumed, nil
	}
	revision := Revision(value)
	if !supported[revision] {
		return "", fmt.Errorf("%w: %q", ErrUnsupportedRevision, value)
	}
	return revision, nil
}

// Stateless reports whether the revision dropped the initialize handshake and
// protocol-level sessions, so each request stands alone.
func (r Revision) Stateless() bool { return r >= Rev20260728 }

// MirrorsHeaders reports whether the revision requires the standard request
// headers that mirror body fields, and therefore whether tailgate validates
// them against the body it forwards.
func (r Revision) MirrorsHeaders() bool { return r >= Rev20260728 }

func (r Revision) String() string { return string(r) }
