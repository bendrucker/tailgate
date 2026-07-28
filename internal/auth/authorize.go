package auth

import (
	"fmt"

	"github.com/bendrucker/tailgate/internal/config"
)

// Reasons recorded on a Decision. They are stable strings so the audit log can
// be filtered on them.
const (
	// ReasonMatched is the only reason that accompanies an allow.
	ReasonMatched = "matched allow rule"
	// ReasonNoIdentity means the caller carried no verified subject, which no
	// rule can match.
	ReasonNoIdentity = "identity has no subject"
	// ReasonNoPolicy means the upstream has no allow rules, so nobody reaches
	// it. An upstream is unreachable until policy names it.
	ReasonNoPolicy = "no policy configured for upstream"
	// ReasonNoMatch means the policy exists and no rule matched the identity.
	ReasonNoMatch = "no allow rule matched the identity"
)

// Authorizer decides whether a verified identity may reach an upstream. Policy
// is allow-only: an identity reaches an upstream when some rule for it matches,
// and is denied otherwise. A nil Authorizer denies everything, so a wiring
// mistake fails closed rather than opening every upstream.
type Authorizer struct {
	rules map[string][]allowRule
}

// allowRule is one config.Match with the position that identifies it in logs.
type allowRule struct {
	name  string
	match config.Match
}

// NewAuthorizer indexes the policy by upstream, preserving configured order.
// Rules are evaluated in that order and the first match wins, so the recorded
// rule is reproducible from the config file.
func NewAuthorizer(policy []config.Rule) *Authorizer {
	a := &Authorizer{rules: make(map[string][]allowRule)}
	for i, rule := range policy {
		for j, match := range rule.Allow {
			a.rules[rule.Upstream] = append(a.rules[rule.Upstream], allowRule{
				name:  fmt.Sprintf("policy[%d].allow[%d]", i, j),
				match: match,
			})
		}
	}
	return a
}

// Authorize evaluates policy for upstream against id and returns the decision
// to serve and to log. Callers pass an Identity that Verify produced; the
// decision is meaningless for an unverified one.
func (a *Authorizer) Authorize(id Identity, upstream string) Decision {
	decision := Decision{Identity: id, Upstream: upstream}
	if id.Subject == "" {
		decision.Reason = ReasonNoIdentity
		return decision
	}
	if a == nil || len(a.rules[upstream]) == 0 {
		decision.Reason = ReasonNoPolicy
		return decision
	}
	for _, rule := range a.rules[upstream] {
		if matchesIdentity(rule.match, id) {
			decision.Allow = true
			decision.Rule = rule.name
			decision.Reason = ReasonMatched
			return decision
		}
	}
	decision.Reason = ReasonNoMatch
	return decision
}

// matchesIdentity reports whether every condition the match states holds for
// id. Conditions are conjunctive, and a match stating none never applies: an
// unconditional rule would allow every identity that ever authenticates.
func matchesIdentity(match config.Match, id Identity) bool {
	conditions := 0
	if match.Subject != "" {
		if match.Subject != id.Subject {
			return false
		}
		conditions++
	}
	if match.Email != "" {
		// tsidp omits email from introspection unless the client requested the
		// email scope, so an absent email denies an email rule.
		if match.Email != id.Email {
			return false
		}
		conditions++
	}
	for name, want := range match.Claim {
		// A condition tailgate cannot evaluate, including a non-string claim,
		// denies rather than being skipped.
		if name == "" || want == "" {
			return false
		}
		got, ok := id.Claims[name].(string)
		if !ok || got != want {
			return false
		}
		conditions++
	}
	return conditions > 0
}
