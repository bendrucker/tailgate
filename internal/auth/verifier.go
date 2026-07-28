package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// tsidp access tokens are opaque strings backed by in-memory state (pinned
// commit 99effa593a17), so the bearer cannot be verified locally against a
// JWKS. Verification is RFC 7662 introspection: tailgate POSTs the token to
// tsidp's introspection endpoint and trusts the response. tsidp authenticates
// the introspection caller by tailnet node identity, which is why the client
// must dial over tsnet (Server.HTTPClient), never the public internet.

// ErrInvalidToken means the bearer failed verification: absent, inactive,
// expired, or not issued for the requested resource. Handlers map it to 401
// with a WWW-Authenticate challenge.
var ErrInvalidToken = errors.New("auth: invalid token")

// Verifier validates bearer tokens by introspecting them against the issuer.
type Verifier struct {
	client        *http.Client
	introspectURL string
	now           func() time.Time
}

// NewVerifier discovers the issuer's introspection endpoint from its OIDC
// metadata. client must reach the issuer with an identity it trusts for
// introspection. For tsidp that means dialing over the tailnet. Construction
// failure means no request can be verified, so callers must treat it as the
// service being unavailable rather than skipping verification.
func NewVerifier(ctx context.Context, client *http.Client, issuer string) (*Verifier, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: discovery: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		Issuer                string `json:"issuer"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("auth: discovery: decode: %w", err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("auth: discovery: issuer mismatch: got %q, want %q", doc.Issuer, issuer)
	}
	if doc.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("auth: discovery: issuer advertises no introspection endpoint")
	}

	return &Verifier{
		client:        client,
		introspectURL: doc.IntrospectionEndpoint,
		now:           time.Now,
	}, nil
}

// Verify introspects the bearer token and returns the caller's identity if the
// token is active, unexpired, and audience-bound to resource. The resource
// string must come from resource.URLs so the audience comparison is byte-exact
// against what the client requested and tsidp granted.
//
// Any verification failure returns ErrInvalidToken. Failure to complete
// introspection at all returns a different error: the caller's token may be
// fine, tailgate just cannot prove it, and the handler maps that to 503 rather
// than challenging the client to re-authenticate.
func (v *Verifier) Verify(ctx context.Context, token, resource string) (Identity, error) {
	if token == "" {
		return Identity{}, fmt.Errorf("%w: empty", ErrInvalidToken)
	}

	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, fmt.Errorf("auth: introspection request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: introspect: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Identity{}, fmt.Errorf("auth: introspect: unexpected status %d", resp.StatusCode)
	}

	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return Identity{}, fmt.Errorf("auth: introspect: decode: %w", err)
	}

	if active, ok := claims["active"].(bool); !ok || !active {
		return Identity{}, fmt.Errorf("%w: not active", ErrInvalidToken)
	}
	now := v.now()
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		return Identity{}, fmt.Errorf("%w: missing exp", ErrInvalidToken)
	}
	if !now.Before(time.Unix(exp, 0)) {
		return Identity{}, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Before(time.Unix(nbf, 0)) {
		return Identity{}, fmt.Errorf("%w: not yet valid", ErrInvalidToken)
	}
	if !audienceContains(claims["aud"], resource) {
		return Identity{}, fmt.Errorf("%w: audience does not include %s", ErrInvalidToken, resource)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return Identity{}, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	email, _ := claims["email"].(string)
	return Identity{Subject: sub, Email: email, Claims: claims}, nil
}

// numericClaim reads a JSON number claim, which decodes as float64 from an
// untyped map.
func numericClaim(claims map[string]any, name string) (int64, bool) {
	f, ok := claims[name].(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

// audienceContains reports whether the RFC 7662 aud value, which may be a
// single string or an array, contains resource exactly. Comparison is
// byte-exact by design: tsidp matches grant resources the same way, and any
// normalization here would let two spellings of one URI pass different checks.
func audienceContains(aud any, resource string) bool {
	switch v := aud.(type) {
	case string:
		return v == resource
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok && s == resource {
				return true
			}
		}
	}
	return false
}
