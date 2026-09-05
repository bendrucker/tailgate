package router

import (
	"net/http"
	"strings"

	"github.com/bendrucker/tailgate/internal/protocol"
)

// protocolStep resolves the revision the request declares and, for a revision
// that mirrors body fields into headers, checks that the pair agree.
//
// tailgate forwards both, so it must not relay a request whose header and body
// disagree even though the upstream is obliged to check them again: the point
// of the mirroring rules is that an intermediary routing on the header and a
// server executing on the body must never be able to read one request two
// ways. tailgate is that intermediary.
//
// The comparison needs the whole body, so the step reads what the body step
// buffered rather than draining the request itself.
type protocolStep struct{ rt *Router }

func (s protocolStep) name() string { return "protocol" }

func (s protocolStep) check(ex *exchange) *refusal {
	r := ex.r
	declared := r.Header.Values(protocol.VersionHeader)
	if len(declared) > 1 {
		// Which copy an intermediary downstream reads is not decidable here,
		// and resolving the revision from the first would let a caller name a
		// revision with no mirroring rules while the upstream reads the last
		// one and executes under them.
		s.rt.logger.Warn("request declares more than one protocol revision", "upstream", ex.up.name)
		return refuseProtocol(protocol.UnsupportedVersion(strings.Join(declared, ", ")))
	}

	revision, err := protocol.Parse(r.Header.Get(protocol.VersionHeader))
	if err != nil {
		s.rt.logger.Debug("unsupported protocol revision", "upstream", ex.up.name, "err", err)
		return refuseProtocol(protocol.UnsupportedVersion(r.Header.Get(protocol.VersionHeader)))
	}
	if r.Method != http.MethodPost {
		// The mirroring contract is about a POST body. A request without one
		// carries no pair that can disagree, and refusing it here would answer
		// a stateless GET or DELETE with a mismatch instead of the 405 the
		// transport owes it. A POST is held to the contract whether or not it
		// carried a body, since an empty one backs no header either.
		return nil
	}
	if !revision.MirrorsHeaders() && !mirrorsAnything(r.Header) {
		return nil
	}
	if err := protocol.ValidateMirrored(r.Header, ex.body); err != nil {
		s.rt.logger.Warn("request headers do not match the body", "upstream", ex.up.name, "err", err)
		return refuseProtocol(protocol.HeaderMismatch(err))
	}
	return nil
}

// mirrorsAnything reports whether the request carries a header the mirroring
// contract governs. The revision that defines those headers is named by the
// caller, so gating validation on it would let a caller carry a mirrored header
// past the check by declaring a revision that has no rules for it, while an
// upstream that reads mirrored headers whatever the declaration executes on the
// pair tailgate never compared.
func mirrorsAnything(header http.Header) bool {
	return header.Get(protocol.MethodHeader) != "" || header.Get(protocol.NameHeader) != ""
}
