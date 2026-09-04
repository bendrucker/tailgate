package cimd

import (
	"errors"
	"strings"
	"testing"
)

func TestParseClientID(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		valid bool
	}{
		{name: "https url with a path", raw: "https://claude.ai/oauth/client", valid: true},
		{name: "root path", raw: "https://example.com/"},
		{name: "port", raw: "https://example.com:8443/client.json", valid: true},
		{name: "query", raw: "https://example.com/client?v=2", valid: true},
		{name: "no path", raw: "https://example.com"},
		{name: "http", raw: "http://example.com/client"},
		{name: "userinfo", raw: "https://user:pass@example.com/client"},
		{name: "fragment", raw: "https://example.com/client#id"},
		{name: "empty fragment", raw: "https://example.com/client#"},
		{name: "single dot segment", raw: "https://example.com/./client"},
		{name: "double dot segment", raw: "https://example.com/a/../client"},
		{name: "no host", raw: "https:///client"},
		{name: "not a url", raw: "://"},
		{name: "empty", raw: ""},
		{name: "uppercase scheme", raw: "HTTPS://example.com/client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseClientID(tc.raw)
			if tc.valid {
				if err != nil {
					t.Fatalf("ParseClientID(%q) = %v", tc.raw, err)
				}
				if parsed.String() != tc.raw {
					t.Errorf("parsed %q back to %q", tc.raw, parsed.String())
				}
				return
			}
			if !errors.Is(err, ErrInvalidClientID) {
				t.Errorf("ParseClientID(%q) = %v, want %v", tc.raw, err, ErrInvalidClientID)
			}
		})
	}
}

func TestParseDocument(t *testing.T) {
	const clientID = "https://claude.ai/oauth/client"
	for _, tc := range []struct {
		name   string
		body   string
		want   *Document
		reason string
	}{
		{
			name: "minimal document",
			body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["https://claude.ai/api/mcp/auth_callback"]}`,
			want: &Document{
				ClientID:     clientID,
				ClientName:   "claude.ai",
				RedirectURIs: []string{"https://claude.ai/api/mcp/auth_callback"},
			},
		},
		{
			name: "full document",
			body: `{"client_id":"https://claude.ai/oauth/client","client_name":"Claude","client_uri":"https://claude.ai","logo_uri":"https://claude.ai/logo.png","redirect_uris":["https://claude.ai/api/mcp/auth_callback","http://localhost/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"]}`,
			want: &Document{
				ClientID:                clientID,
				ClientName:              "Claude",
				ClientURI:               "https://claude.ai",
				RedirectURIs:            []string{"https://claude.ai/api/mcp/auth_callback", "http://localhost/callback"},
				TokenEndpointAuthMethod: "none",
			},
		},
		{
			name: "custom scheme redirect",
			body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["com.example.app:/callback"]}`,
			want: &Document{
				ClientID:     clientID,
				ClientName:   "claude.ai",
				RedirectURIs: []string{"com.example.app:/callback"},
			},
		},
		{name: "not json", body: `<html>`, reason: "invalid character"},
		{name: "client id mismatch", body: `{"client_id":"https://claude.ai/oauth/other","redirect_uris":["https://claude.ai/cb"]}`, reason: "client_id does not match"},
		{name: "client id missing", body: `{"redirect_uris":["https://claude.ai/cb"]}`, reason: "client_id does not match"},
		{name: "client secret", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["https://claude.ai/cb"],"client_secret":"s"}`, reason: "client secret"},
		{name: "client secret expiry", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["https://claude.ai/cb"],"client_secret_expires_at":0}`, reason: "client secret"},
		{name: "secret auth method", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["https://claude.ai/cb"],"token_endpoint_auth_method":"client_secret_basic"}`, reason: "token_endpoint_auth_method"},
		{name: "no redirect uris", body: `{"client_id":"https://claude.ai/oauth/client"}`, reason: "redirect_uris is required"},
		{name: "empty redirect uris", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":[]}`, reason: "redirect_uris is required"},
		{name: "relative redirect uri", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["/callback"]}`, reason: "must be absolute"},
		{name: "redirect uri with fragment", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["https://claude.ai/cb#x"]}`, reason: "fragment"},
		{name: "plain http redirect uri", body: `{"client_id":"https://claude.ai/oauth/client","redirect_uris":["http://claude.ai/cb"]}`, reason: "loopback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parseDocument(clientID, []byte(tc.body))
			if tc.want != nil {
				if err != nil {
					t.Fatalf("parseDocument: %v", err)
				}
				assertDocument(t, tc.want, doc)
				return
			}
			if !errors.Is(err, ErrInvalidDocument) {
				t.Fatalf("parseDocument error = %v, want %v", err, ErrInvalidDocument)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %q does not name %q", err, tc.reason)
			}
		})
	}
}

func assertDocument(t *testing.T, want, got *Document) {
	t.Helper()
	if got.ClientID != want.ClientID || got.ClientName != want.ClientName || got.ClientURI != want.ClientURI || got.TokenEndpointAuthMethod != want.TokenEndpointAuthMethod {
		t.Errorf("document = %+v, want %+v", got, want)
	}
	if strings.Join(got.RedirectURIs, " ") != strings.Join(want.RedirectURIs, " ") {
		t.Errorf("redirect_uris = %v, want %v", got.RedirectURIs, want.RedirectURIs)
	}
}
