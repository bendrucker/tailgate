package router

import (
	"net/http"
	"strings"

	"github.com/bendrucker/tailgate/internal/protocol"
)

// checkProtocol resolves the revision the request declares and, for a revision
// that mirrors body fields into headers, checks that the pair agree.
//
// tailgate forwards both, so it must not relay a request whose header and body
// disagree even though the upstream is obliged to check them again: the point
// of the mirroring rules is that an intermediary routing on the header and a
// server executing on the body must never be able to read one request two
// ways. tailgate is that intermediary.
//
// The check runs after the body is buffered, which is the only point where
// tailgate holds both halves, and after authorization, so an unauthenticated
// caller learns nothing about the upstream's protocol from the shape of the
// refusal.
func (rt *Router) checkProtocol(rec *responseRecorder, r *http.Request, up *upstream, body []byte) bool {
	declared := r.Header.Values(protocol.VersionHeader)
	if len(declared) > 1 {
		// Which copy an intermediary downstream reads is not decidable here,
		// and resolving the revision from the first would let a caller name a
		// revision with no mirroring rules while the upstream reads the last
		// one and executes under them.
		rt.logger.Warn("request declares more than one protocol revision", "upstream", up.name)
		protocol.WriteUnsupportedVersion(rec, strings.Join(declared, ", "))
		return false
	}

	revision, err := protocol.Parse(r.Header.Get(protocol.VersionHeader))
	if err != nil {
		rt.logger.Debug("unsupported protocol revision", "upstream", up.name, "err", err)
		protocol.WriteUnsupportedVersion(rec, r.Header.Get(protocol.VersionHeader))
		return false
	}
	if !revision.MirrorsHeaders() || r.Method != http.MethodPost {
		// The mirroring contract is about a POST body. A request without one
		// carries no pair that can disagree, and refusing it here would answer
		// a stateless GET or DELETE with a mismatch instead of the 405 the
		// transport owes it. A POST is held to the contract whether or not it
		// carried a body, since an empty one backs no header either.
		return true
	}
	if err := protocol.ValidateMirrored(r.Header, body); err != nil {
		rt.logger.Warn("request headers do not match the body", "upstream", up.name, "err", err)
		protocol.WriteHeaderMismatch(rec, err)
		return false
	}
	return true
}
