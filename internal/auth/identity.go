// Package auth verifies OIDC tokens and authorizes identities against policy.
//
// tsidp access tokens are opaque, so verification is RFC 7662 introspection
// over tsnet. No token is verified locally anywhere in this package, and no
// JOSE or JWT dependency belongs here.
package auth

// Identity is the validated caller extracted from a tsidp token. It carries the
// stable identifiers plus the full claim set, so policy can match on any claim
// without changing this contract.
type Identity struct {
	Subject string
	Email   string
	Claims  map[string]any
}

// Decision is the outcome of an authorization check. It is recorded verbatim in
// the audit log.
type Decision struct {
	Identity Identity
	Upstream string
	Allow    bool
	Reason   string
	// Rule names the allow condition that matched, as "policy[i].allow[j]"
	// against the configured policy. It is empty on a denial, where Reason
	// carries why no rule applied.
	Rule string
}
