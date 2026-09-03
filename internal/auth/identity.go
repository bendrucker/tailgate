// Package auth issues and verifies tailgate's bearer tokens and authorizes
// identities against policy.
//
// tailgate is its own issuer. Tokens are opaque random strings looked up in
// memory, so nothing is signed, nothing is parsed, and no JOSE or JWT
// dependency belongs here. A restart forgets every token, and clients recover
// through the ordinary 401 challenge.
package auth

// Identity is the person a token was issued to. Subject is the bare decimal
// tailnet user ID and Email the tailnet login name. Claims carries both plus
// the grant's scope, client, and audience, so policy can match on any of them
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
