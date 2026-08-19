package proxy

import (
	"net/http"
	"strings"
)

// IdentityHeaderPrefix is reserved for headers tailgate sets about the caller.
// Inbound headers matching it are stripped, so a client can never present one
// and have an upstream mistake it for tailgate's assertion.
const IdentityHeaderPrefix = "X-Tailgate-"

// strippedHeaders are the exact names an upstream could mistake for an
// assertion about the caller. Cookie is here because every upstream, the
// authorization server facade, the metadata documents, and the site share one
// Funnel origin, so a browser sends one origin's cookie to whichever upstream
// the path names.
var strippedHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"Forwarded",
	"Cookie",
	"X-Real-IP",
	"X-Original-URL",
	"X-Rewrite-URL",
}

// StripRequest removes everything an upstream could mistake for an assertion
// about the caller: the client's bearer token, proxy credentials, and the
// forwarding and identity headers only tailgate may state.
//
// Trailers are cleared alongside the headers because they are a second header
// map on the same request. Go's server accepts a trailer announcing any name,
// r.Clone copies the map, and http.Transport re-emits it after the body, so a
// name refused in the header arrives at the upstream regardless. That defeats
// every decision tailgate makes from a header, since tailgate reads the map it
// validated while the upstream reads both.
//
// It lives on the seam because the no-token-passthrough invariant must not
// depend on caller discipline: the router strips before dispatch, and each
// transport strips again on the way out.
func StripRequest(r *http.Request) {
	StripCredentials(r.Header)
	r.Trailer = nil
	r.Header.Del("Trailer")
}

// StripCredentials strips one header map. Callers holding a whole request want
// StripRequest, which also clears the trailers.
func StripCredentials(header http.Header) {
	for _, name := range strippedHeaders {
		header.Del(name)
	}
	for name := range header {
		if hasPrefixFold(name, "X-Forwarded-") || hasPrefixFold(name, IdentityHeaderPrefix) {
			delete(header, name)
		}
	}
}

// hasPrefixFold compares case-insensitively and treats an underscore as a
// hyphen. Underscore is a valid token byte that canonicalization leaves alone,
// so X_Tailgate_Subject is a distinct map key from X-Tailgate-Subject, and a
// CGI-style upstream folds the two back together into one variable name.
func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return strings.EqualFold(strings.ReplaceAll(s[:len(prefix)], "_", "-"), prefix)
}
