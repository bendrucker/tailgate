package router

import "net/http"

// authorizeStep evaluates policy for the authenticated identity. It is the one
// step that records a decision when it passes as well as when it refuses,
// because the allow is the decision the audit log exists for.
type authorizeStep struct{ rt *Router }

func (s authorizeStep) name() string { return "authorize" }

func (s authorizeStep) check(ex *exchange) *refusal {
	decision := s.rt.authorizer.Authorize(ex.identity, ex.up.name)
	if !decision.Allow {
		return deny(http.StatusForbidden, "forbidden", decision)
	}
	s.rt.audit.Record(ex.r.Context(), decision)
	return nil
}
