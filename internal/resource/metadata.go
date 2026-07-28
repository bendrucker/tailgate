package resource

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// bearerMethodsSupported advertises that tailgate reads the token from the
// Authorization header only. Query and form-body bearers (RFC 6750 sections
// 2.2 and 2.3) leak tokens into logs and referrers, and the router never looks
// for them.
var bearerMethodsSupported = []string{"header"}

// scopesSupported are the scopes a client must request for tailgate to
// authorize it. tsidp omits email from introspection unless the token carries
// the email scope, and the shipped email-allowlist policy then denies every
// request from that client, so email is advertised as required rather than
// optional.
var scopesSupported = []string{"openid", "email"}

// Metadata is one upstream's RFC 9728 protected-resource metadata document.
// Resource is the byte-exact canonical URI from URLs.ResourceURL, which is
// also the resource value the client sends on the token request and the aud
// value tsidp grants.
type Metadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
}

// Handler serves the protected-resource metadata for the configured upstreams
// at their path-suffix well-known locations. It is the discovery half of the
// resource server: a client that gets a 401 reads resource_metadata from the
// challenge, fetches the document from here, and learns which authorization
// server issues tokens for that resource.
//
// Discovery is unauthenticated by design, so the documents are built once at
// construction and served from memory.
type Handler struct {
	documents map[string][]byte
}

// NewHandler builds the metadata documents for the named upstreams, naming
// issuer as their authorization server. issuer must be the same string the
// verifier discovers against, since a client that trusts this document will
// obtain tokens from it.
func NewHandler(urls *URLs, issuer string, upstreams []string) (*Handler, error) {
	if urls == nil {
		return nil, fmt.Errorf("resource: nil URLs")
	}
	authorizationServer, err := canonicalIssuer(issuer)
	if err != nil {
		return nil, err
	}

	documents := make(map[string][]byte, len(upstreams))
	for _, name := range upstreams {
		if err := validateUpstreamName(name); err != nil {
			return nil, err
		}
		if _, ok := documents[name]; ok {
			return nil, fmt.Errorf("resource: duplicate upstream %q", name)
		}
		doc, err := json.Marshal(Metadata{
			Resource:               urls.ResourceURL(name),
			AuthorizationServers:   []string{authorizationServer},
			BearerMethodsSupported: bearerMethodsSupported,
			ScopesSupported:        scopesSupported,
		})
		if err != nil {
			return nil, fmt.Errorf("resource: encode metadata for %q: %w", name, err)
		}
		documents[name] = doc
	}
	return &Handler{documents: documents}, nil
}

// ServeHTTP answers the metadata request. Requests for anything other than a
// configured upstream's document get 404, so the handler is safe to mount on
// the whole well-known subtree.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	doc, ok := h.document(r.URL)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(doc)))
	w.Write(doc)
}

// document resolves a request URL to a metadata document. The path must be the
// well-known prefix followed by one segment that is an exact configured
// upstream name. Nothing is cleaned or decoded first, so /mcp/x/../y and
// /mcp/%67ithub resolve to no document rather than aliasing one.
func (h *Handler) document(u *url.URL) ([]byte, bool) {
	if u.EscapedPath() != u.Path {
		return nil, false
	}
	name, ok := strings.CutPrefix(u.Path, MetadataPathPrefix+"/mcp/")
	if !ok {
		return nil, false
	}
	doc, ok := h.documents[name]
	return doc, ok
}

// canonicalIssuer normalizes the issuer identifier the same way the verifier
// does, so the authorization server a client discovers here is the one that
// issued the token the verifier will accept.
func canonicalIssuer(issuer string) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("resource: parse issuer %q: %w", issuer, err)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("resource: issuer %q must be an http or https URL", issuer)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("resource: issuer %q has no host", issuer)
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("resource: issuer %q must have no query or fragment", issuer)
	}
	return trimmed, nil
}

func validateUpstreamName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/%?#") || name != url.PathEscape(name) {
		return fmt.Errorf("resource: upstream name %q is not a single path segment", name)
	}
	return nil
}
