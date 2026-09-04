// Package cimd resolves OAuth clients identified by Client ID Metadata
// Documents, per draft-ietf-oauth-client-id-metadata-document.
//
// A client's client_id is an HTTPS URL. The document at that URL carries the
// client's redirect URIs and display name, so the authorization server needs
// no registry of clients and no shared secret: the client is public, proves
// possession of nothing, and is bound to its redirect URIs by the document
// its own origin publishes. claude.ai and FastMCP identify themselves this way.
//
// Fetching a URL a stranger chose is an egress path off an internet-facing
// process, so the production client refuses every address that is not global
// unicast, follows no redirects, and bounds the document's size and the
// round trip. The Fetcher caches documents by the cache lifetime the origin
// asks for, clamped, and never caches a failure.
package cimd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	// ErrInvalidClientID means the client_id is not a usable metadata document
	// URL. The rules are the draft's: https, a host, a path, and no userinfo,
	// fragment, or dot segments.
	ErrInvalidClientID = errors.New("cimd: invalid client_id")
	// ErrInvalidDocument means the document was fetched but does not describe
	// the client that named it, or describes one this server cannot serve.
	ErrInvalidDocument = errors.New("cimd: invalid client metadata document")
	// ErrFetch means the document could not be retrieved: the origin refused,
	// answered with something other than a JSON document, or was unreachable.
	ErrFetch = errors.New("cimd: fetching client metadata document")
)

// maxDocumentBytes bounds a document. The draft recommends origins keep
// documents under 5 kilobytes, and the bound here is generous against that
// without letting a hostile origin spend memory.
const maxDocumentBytes = 16 << 10

// Document is the client metadata tailgate uses. Everything else in the
// document is ignored.
type Document struct {
	// ClientID is the document URL, which the document must repeat exactly.
	ClientID string `json:"client_id"`
	// ClientName is what the consent page shows. It falls back to the client
	// ID's host when the document names none.
	ClientName string `json:"client_name"`
	ClientURI  string `json:"client_uri"`
	// RedirectURIs are the only redirect targets the client may name on an
	// authorization request.
	RedirectURIs []string `json:"redirect_uris"`
	// TokenEndpointAuthMethod must be "none" or absent. A metadata document
	// cannot carry a secret, so it cannot register a confidential client.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
}

// ParseClientID checks that raw is a client identifier URL the draft permits
// and returns it parsed. The document's own client_id must equal raw byte for
// byte, so the caller keeps raw as the client's identity and uses the parsed
// form only for fetching and display.
func ParseClientID(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientID, err)
	}
	switch {
	case parsed.Scheme != "https":
		return nil, fmt.Errorf("%w: scheme must be https", ErrInvalidClientID)
	case parsed.Host == "" || parsed.Hostname() == "":
		return nil, fmt.Errorf("%w: no host", ErrInvalidClientID)
	case parsed.User != nil:
		return nil, fmt.Errorf("%w: userinfo is not allowed", ErrInvalidClientID)
	case parsed.Fragment != "" || parsed.RawFragment != "" || strings.HasSuffix(raw, "#"):
		return nil, fmt.Errorf("%w: fragment is not allowed", ErrInvalidClientID)
	case parsed.Path == "" || parsed.Path == "/":
		return nil, fmt.Errorf("%w: a path component is required", ErrInvalidClientID)
	}
	for segment := range strings.SplitSeq(parsed.EscapedPath(), "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("%w: dot segments are not allowed", ErrInvalidClientID)
		}
	}
	if parsed.String() != raw {
		return nil, fmt.Errorf("%w: not in canonical form", ErrInvalidClientID)
	}
	return parsed, nil
}

// wireDocument is the document as decoded, with the fields whose presence
// alone makes it invalid.
type wireDocument struct {
	Document
	ClientSecret          json.RawMessage `json:"client_secret"`
	ClientSecretExpiresAt json.RawMessage `json:"client_secret_expires_at"`
}

// parseDocument decodes and validates a document fetched for clientID.
func parseDocument(clientID string, body []byte) (*Document, error) {
	var wire wireDocument
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	doc := wire.Document
	switch {
	case doc.ClientID != clientID:
		return nil, fmt.Errorf("%w: client_id does not match the document URL", ErrInvalidDocument)
	case wire.ClientSecret != nil || wire.ClientSecretExpiresAt != nil:
		return nil, fmt.Errorf("%w: a metadata document cannot carry a client secret", ErrInvalidDocument)
	case doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none":
		return nil, fmt.Errorf("%w: token_endpoint_auth_method %q is not supported, only none", ErrInvalidDocument, doc.TokenEndpointAuthMethod)
	case len(doc.RedirectURIs) == 0:
		return nil, fmt.Errorf("%w: redirect_uris is required", ErrInvalidDocument)
	}
	for _, redirect := range doc.RedirectURIs {
		if err := validateRedirectURI(redirect); err != nil {
			return nil, fmt.Errorf("%w: redirect_uri %q: %v", ErrInvalidDocument, redirect, err)
		}
	}
	if doc.ClientName == "" {
		parsed, err := url.Parse(clientID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
		}
		doc.ClientName = parsed.Hostname()
	}
	return &doc, nil
}

// validateRedirectURI applies what RFC 6749 section 3.1.2 requires of a
// registered redirect URI: absolute, and free of a fragment.
func validateRedirectURI(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case parsed.Scheme == "":
		return errors.New("must be absolute")
	case parsed.Fragment != "" || parsed.RawFragment != "" || strings.HasSuffix(raw, "#"):
		return errors.New("must not carry a fragment")
	case parsed.Scheme == "http" && !IsLoopbackHost(parsed.Hostname()):
		return errors.New("http is allowed only for loopback")
	case (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() == "":
		return errors.New("has no host")
	}
	return nil
}

// IsLoopbackHost reports whether host is one RFC 8252 section 7.3 treats as a
// native app's loopback redirect target.
func IsLoopbackHost(host string) bool {
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
