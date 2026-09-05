package router

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/bendrucker/tailgate/internal/auth"
)

// originStep validates the browser origin against DNS rebinding. A request
// with no Origin header is not from a browser and passes. A request that
// carries one must name an origin tailgate is served from.
//
// It guards every path tailgate serves rather than upstreams alone, so
// [Router.route] runs it ahead of routing and it is the one step that sees an
// exchange whose upstream is still nil.
type originStep struct{ rt *Router }

func (s originStep) name() string { return "origin" }

func (s originStep) check(ex *exchange) *refusal {
	if s.rt.originAllowed(ex.r) {
		return nil
	}
	// The audit record names an upstream only once the path resolved to a
	// configured one, which is what upstreamName reports.
	return deny(http.StatusForbidden, "forbidden origin",
		denied(auth.Identity{}, ex.upstreamName(), ReasonOriginNotAllowed))
}

// originAllowed reports whether the request's Origin header, if it carries
// one, names an allowed origin.
//
// Repeated headers are refused rather than resolved to the first. tailgate
// forwards the header, so an upstream that reads the last one would execute
// against an origin tailgate never validated.
func (rt *Router) originAllowed(r *http.Request) bool {
	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 0 || origins[0] == "" {
		return true
	}
	return rt.origins[normalizeOrigin(origins[0])]
}

// normalizeOrigin reduces an origin to scheme and authority with the scheme's
// default port removed, so one origin has one spelling on both sides of the
// comparison. It returns "" for anything that is not an absolute origin,
// including the opaque "null" origin, which then matches no allowlist entry.
func normalizeOrigin(origin string) string {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	scheme, hostname := strings.ToLower(parsed.Scheme), strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return ""
	}
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	switch scheme {
	case "http", "https":
	default:
		return ""
	}
	// Hostname strips the brackets an IPv6 literal needs, and an authority that
	// cannot be reparsed is not a canonical form.
	host := hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}
