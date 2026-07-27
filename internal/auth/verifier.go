package auth

import (
	"context"

	"github.com/coreos/go-oidc/v3/oidc"
)

// NewVerifier builds an OIDC verifier for one upstream's audience, which is the
// upstream's canonical resource URI. tsidp is the issuer and go-oidc fetches and
// caches its JWKS.
//
// Caveat: go-oidc's verifier is built for ID tokens. The bearer token an MCP
// client presents is an access token. Whether it can be verified here depends on
// tsidp issuing access tokens as JWTs that carry aud. See "Must resolve first"
// in CLAUDE.md before relying on this path.
func NewVerifier(ctx context.Context, issuer, audience string) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return provider.Verifier(&oidc.Config{ClientID: audience}), nil
}
