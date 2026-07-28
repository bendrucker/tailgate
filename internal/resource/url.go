// Package resource identifies each upstream as an OAuth protected resource and
// serves its discovery metadata.
package resource

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// URLs mints the canonical resource URI for each upstream. The same string must
// match byte-for-byte across the client's resource parameter, the token's aud
// claim, the verifier's expected audience, and the protected-resource metadata
// document, so every consumer goes through this type and none constructs the
// URI itself.
//
// The tailnet FQDN is unknown until the tsnet node joins, so construct URLs
// after join and thread it through the spine.
type URLs struct {
	base *url.URL
}

// NewURLs canonicalizes the node's FQDN and Funnel port into the base all
// resource URIs share: lowercase https host, no trailing dot, and the port
// omitted when it is 443.
func NewURLs(fqdn string, port int) (*URLs, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fqdn), "."))
	if host == "" {
		return nil, fmt.Errorf("resource: empty FQDN")
	}
	if strings.ContainsAny(host, "/:?#") {
		return nil, fmt.Errorf("resource: FQDN %q must be a bare host", fqdn)
	}
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return &URLs{base: &url.URL{Scheme: "https", Host: host, Path: "/"}}, nil
}

// ResourceURL returns the canonical URI identifying the named upstream as a
// protected resource: <base>/mcp/<name>, with no trailing slash, query, or
// fragment.
func (u *URLs) ResourceURL(name string) string {
	return u.base.JoinPath("mcp", name).String()
}

// Metadata returns the path serving the RFC 9728 protected-resource metadata
// for the named upstream: the well-known prefix inserted ahead of the resource
// path, per RFC 9728 section 3.
func (u *URLs) Metadata(name string) string {
	return u.base.JoinPath(".well-known", "oauth-protected-resource", "mcp", name).Path
}
