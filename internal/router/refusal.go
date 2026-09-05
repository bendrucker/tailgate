package router

import (
	"maps"
	"net/http"

	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/protocol"
)

// refusal is a step's decision to end a request. It carries the three things
// answering one takes: the status, the body, and the authorization decision
// the audit log records. They travel together because settling one without the
// others is how a caller gets turned away with nothing in the decision log, or
// gets a status in a shape that tells it something untrue about the server.
//
// Four constructors build one, and choosing among them settles all three.
// [refuseProtocol] and [denyProtocol] answer 400, the one status whose body
// format carries a protocol meaning, and take the JSON-RPC error object that
// body needs. [refuse] and [deny] answer everything else in status text. The
// deny pair record an authorization decision, the refuse pair record none.
type refusal struct {
	status int
	// text is the response body wherever the format is status text.
	text string
	// rpc is the JSON-RPC error object a 400 answers with.
	rpc protocol.ErrorObject
	// header holds response fields the refusal carries beyond its body, such
	// as the WWW-Authenticate challenge naming where a token comes from.
	header http.Header
	// decision is the authorization decision to record, or nil when the
	// request was refused without one being reached.
	decision *auth.Decision
}

// refuse answers status in status text, recording no authorization decision.
// It is for a request refused before any policy question arose, or after the
// decision was already recorded.
func refuse(status int, text string) *refusal {
	return &refusal{status: status, text: text}
}

// deny is [refuse] for a refusal that is itself an authorization decision.
func deny(status int, text string, d auth.Decision) *refusal {
	return &refusal{status: status, text: text, decision: &d}
}

// refuseProtocol answers 400 with rpc as the body, recording no authorization
// decision.
func refuseProtocol(rpc protocol.ErrorObject) *refusal {
	return &refusal{status: http.StatusBadRequest, rpc: rpc}
}

// denyProtocol is [refuseProtocol] for a refusal that is itself an
// authorization decision.
func denyProtocol(rpc protocol.ErrorObject, d auth.Decision) *refusal {
	return &refusal{status: http.StatusBadRequest, rpc: rpc, decision: &d}
}

// withHeader adds a response field the refusal carries beyond its body.
func (ref *refusal) withHeader(name, value string) *refusal {
	if ref.header == nil {
		ref.header = make(http.Header, 1)
	}
	ref.header.Set(name, value)
	return ref
}

// write answers the request with the refusal, in the body format its status
// calls for.
//
// 400 is the one status a client reads as a statement about the server rather
// than about its own request: a client probing for the server's protocol era
// falls back to the initialize handshake older revisions used when a 400
// carries a body it cannot recognize as a JSON-RPC error. Bare text there
// talks callers into revisions with weaker rules, so the status alone decides
// the format and no 400 tailgate originates can leave in any other shape.
//
// Every other status answers in status text, whose detail names nothing about
// the upstream, the identity, or tailgate's internals. docs/security.md
// records the rule under "JSON-RPC Refusals".
func (ref *refusal) write(w http.ResponseWriter) {
	maps.Copy(w.Header(), ref.header)
	if ref.status != http.StatusBadRequest {
		http.Error(w, ref.text, ref.status)
		return
	}
	rpc := ref.rpc
	if rpc.Code == 0 {
		// A 400 built without an error object came from a step that took the
		// text constructors, which is a mistake rather than a shape to send.
		// The generic code stands in so the answer still reads as a refusal.
		message := ref.text
		if message == "" {
			message = http.StatusText(ref.status)
		}
		rpc = protocol.ErrorObject{Code: protocol.CodeInvalidRequest, Message: message}
	}
	rpc.Write(w, ref.status)
}

// denied is the audit decision a refusal records for a request turned away
// without a policy evaluation, which is every refusal but the policy denial
// itself. upstream is empty when the request path resolved to no configured
// upstream: the segment is caller-supplied, so auditing it unresolved would
// let an unauthenticated client write arbitrary values into the decision log.
func denied(id auth.Identity, upstream, reason string) auth.Decision {
	return auth.Decision{Identity: id, Upstream: upstream, Reason: reason}
}
