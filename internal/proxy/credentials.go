package proxy

import (
	"net/http"
	"strings"
)

// IdentityHeaderPrefix is reserved for headers tailgate sets about the caller.
// Inbound headers matching it are stripped, so a client can never present one
// and have an upstream mistake it for tailgate's assertion.
const IdentityHeaderPrefix = "X-Tailgate-"

// StripCredentials removes everything an upstream could mistake for an
// assertion about the caller: the client's bearer token, proxy credentials, and
// the forwarding and identity headers only tailgate may state.
//
// It lives on the seam because the no-token-passthrough invariant must not
// depend on caller discipline: the router strips before dispatch, and each
// transport strips again on the way out.
func StripCredentials(header http.Header) {
	header.Del("Authorization")
	header.Del("Proxy-Authorization")
	header.Del("Forwarded")
	for name := range header {
		if hasPrefixFold(name, "X-Forwarded-") || hasPrefixFold(name, IdentityHeaderPrefix) {
			delete(header, name)
		}
	}
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}
