// Package site serves tailgate's unauthenticated origin surface: the root
// page and the favicon.
//
// The surface exists for icon crawlers. claude.ai renders a custom
// connector's icon by asking Google's favicon service for the connector
// domain's icon, and that service indexes what the origin serves at
// /favicon.ico and the icon link on its root page. An origin serving neither
// falls back to the parent domain's icon, which for a *.ts.net node is
// Tailscale's logo rather than anything naming the deployment.
//
// The icon is deployment-specific and configured by path rather than embedded:
// tailgate fronts arbitrary upstreams, so no one image belongs in the binary,
// and an operator branding the gateway with an upstream's own icon keeps that
// asset out of this repository.
package site

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Paths the site serves, both on tailgate's origin.
const (
	// RootPath serves a minimal page whose icon link points crawlers at the
	// favicon.
	RootPath = "/"
	// FaviconPath serves the configured icon.
	FaviconPath = "/favicon.ico"
)

// root is the whole page: enough for an icon crawler to find the favicon
// link, and nothing that would make the origin worth probing further.
const root = `<!doctype html>
<html>
<head><title>tailgate</title><link rel="icon" href="/favicon.ico"></head>
<body>tailgate MCP gateway</body>
</html>
`

// Site serves the origin surface. It is safe for concurrent use.
type Site struct {
	icon     []byte
	iconType string
}

// New loads the favicon at path. The file is read once here: the icon is part
// of the deployment, and startup is where a missing or unreadable file can
// still fail the process rather than turning into per-request 500s.
func New(path string) (*Site, error) {
	icon, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("site: read favicon: %w", err)
	}
	if len(icon) == 0 {
		return nil, fmt.Errorf("site: favicon %s is empty", path)
	}
	contentType := http.DetectContentType(icon)
	// The type is sniffed from the bytes, so a file that is not an image is
	// served as whatever it parses as. An HTML one would put attacker-authored
	// script on the only origin tailgate trusts.
	if !strings.HasPrefix(contentType, "image/") {
		return nil, fmt.Errorf("site: favicon %s is %s, not an image", path, contentType)
	}
	return &Site{icon: icon, iconType: contentType}, nil
}

// Handles reports whether the site owns a path, so the router can dispatch
// without duplicating the path set.
func (s *Site) Handles(path string) bool {
	return path == RootPath || path == FaviconPath
}

// ServeHTTP answers the two site paths. Both are public documents, so the
// only method question is GET versus HEAD, and both are cacheable: the icon
// changes only with a redeploy, and a crawler that honors the header stops
// re-fetching it.
func (s *Site) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body := []byte(root)
	contentType := "text/html; charset=utf-8"
	if r.URL.Path == FaviconPath {
		body = s.icon
		contentType = s.iconType
	}

	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	w.Write(body)
}

var _ http.Handler = (*Site)(nil)
