package router

import (
	"net/http"

	"github.com/bendrucker/tailgate/internal/auth"
)

// exchange is one request on its way through the pipeline. Each step reads it,
// leaves behind whatever the steps after it need, and passes it on.
type exchange struct {
	rec *responseRecorder
	r   *http.Request
	// up is the upstream the request path names, or nil when it names none.
	// Only the origin step sees a nil one: it guards every path tailgate
	// serves, so it runs before routing settles which upstream, if any, the
	// request addresses.
	up *upstream

	// identity is what the authenticate step proved about the caller. It is
	// the zero identity until then, and the only identity tailgate hands an
	// upstream.
	identity auth.Identity
	// body is the request body the body step buffered. The steps after it read
	// what will be forwarded rather than draining the request themselves.
	body []byte
	// release ends the session hold the session step took, and is nil when it
	// took none.
	release func()
}

// upstreamName is the name to record about the request, empty until routing
// resolves the path to a configured upstream.
func (ex *exchange) upstreamName() string {
	if ex.up == nil {
		return ""
	}
	return ex.up.name
}

// releaseSession ends the session hold, whether the request dispatched or a
// later step refused it. A hold left behind occupies its binding until the TTL
// expires it.
func (ex *exchange) releaseSession() {
	if ex.release != nil {
		ex.release()
	}
}

// step is one check a request passes. Every step reads the exchange and
// returns nil to pass the request on, or a refusal that ends it.
//
// One signature for every check is what makes the order a value instead of a
// call sequence: [Router.pipeline] is a slice of these, so the ordering the
// security argument rests on is something a test reads rather than something
// spread across a function body.
type step interface {
	// name identifies the step wherever the pipeline is described: the order
	// test, and the log line a refusal writes.
	name() string
	// check runs the step against the request in flight.
	check(ex *exchange) *refusal
}

// newPipeline returns the steps an upstream request passes, in order.
//
// Two orderings here carry a security argument that nothing else enforces:
//
//   - Authentication precedes body limiting, so a caller who never
//     authenticates never has a body buffered on its behalf, and no
//     authentication decision can turn on a body the caller chose.
//   - Authentication precedes protocol validation, so an unauthenticated
//     caller learns nothing about the upstream's protocol era from a mismatch
//     refusal.
//
// The protocol step also reads the body the body step buffered, so it can only
// run after it. TestPipelineOrder and TestAuthenticationPrecedesEveryOtherCheck
// are what hold all three.
//
// The origin check is not here. It guards every path tailgate serves rather
// than upstreams alone, so [Router.route] runs it ahead of routing.
func newPipeline(rt *Router) []step {
	return []step{
		authenticateStep{rt},
		authorizeStep{rt},
		sessionStep{rt},
		bodyStep{rt},
		protocolStep{rt},
	}
}

// serveUpstream runs the pipeline and dispatches whatever survives it.
func (rt *Router) serveUpstream(ex *exchange) {
	defer ex.releaseSession()

	for _, s := range rt.pipeline {
		ref := s.check(ex)
		if ref == nil {
			continue
		}
		rt.logger.Debug("request refused", "step", s.name(), "status", ref.status, "upstream", ex.upstreamName())
		rt.answer(ex, ref)
		return
	}
	rt.dispatch(ex)
}

// answer records the refusal's authorization decision and writes it. Every
// refusal the router sends goes through here, so a decision cannot reach the
// wire without being recorded.
func (rt *Router) answer(ex *exchange, ref *refusal) {
	if ref.decision != nil {
		rt.audit.Record(ex.r.Context(), *ref.decision)
	}
	ref.write(ex.rec)
}
