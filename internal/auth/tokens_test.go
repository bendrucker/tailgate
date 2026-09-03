package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const testResource = "https://gate.example.ts.net/mcp/docs"

func testGrant() Grant {
	return Grant{
		Identity: Identity{
			Subject: "12345",
			Email:   "person@example.com",
			Claims:  map[string]any{"name": "A Person", "groups": []any{"admins"}},
		},
		ClientID: "https://client.example.com/oauth/client",
		Resource: testResource,
		Scopes:   []string{"openid", "email"},
	}
}

type testClock struct {
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Unix(1_800_000_000, 0)}
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestTokensIssueAndVerify(t *testing.T) {
	clock := newTestClock()
	tokens := NewTokens(WithClock(clock.Now))
	issued := tokens.Issue(testGrant())

	if issued.ExpiresIn != DefaultAccessTokenTTL {
		t.Errorf("ExpiresIn = %v, want %v", issued.ExpiresIn, DefaultAccessTokenTTL)
	}
	if issued.AccessToken == issued.RefreshToken {
		t.Fatal("access and refresh tokens are the same string")
	}
	for _, token := range []string{issued.AccessToken, issued.RefreshToken} {
		if err := validateTokenSyntax(token); err != nil {
			t.Errorf("minted token %q fails syntax: %v", token, err)
		}
		if len(token) != 43 {
			t.Errorf("minted token is %d characters, want 43", len(token))
		}
	}

	id, err := tokens.Verify(t.Context(), issued.AccessToken, testResource)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := Identity{
		Subject: "12345",
		Email:   "person@example.com",
		Claims: map[string]any{
			"name":      "A Person",
			"groups":    []any{"admins"},
			"sub":       "12345",
			"email":     "person@example.com",
			"scope":     "openid email",
			"client_id": "https://client.example.com/oauth/client",
			"aud":       testResource,
			"iat":       clock.now.Unix(),
			"exp":       clock.now.Add(DefaultAccessTokenTTL).Unix(),
		},
	}
	if diff := cmp.Diff(want, id); diff != "" {
		t.Errorf("identity mismatch (-want +got):\n%s", diff)
	}
}

func TestTokensVerifyRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    func(tokens *Tokens, issued Issued) string
		resource string
		advance  time.Duration
		want     error
	}{
		{
			name:     "unknown token",
			token:    func(*Tokens, Issued) string { return newToken() },
			resource: testResource,
			want:     ErrInvalidToken,
		},
		{
			name:     "refresh token as a bearer",
			token:    func(_ *Tokens, issued Issued) string { return issued.RefreshToken },
			resource: testResource,
			want:     ErrInvalidToken,
		},
		{
			name:     "expired access token",
			token:    func(_ *Tokens, issued Issued) string { return issued.AccessToken },
			resource: testResource,
			advance:  DefaultAccessTokenTTL,
			want:     ErrInvalidToken,
		},
		{
			name:     "another resource",
			token:    func(_ *Tokens, issued Issued) string { return issued.AccessToken },
			resource: "https://gate.example.ts.net/mcp/other",
			want:     ErrInvalidToken,
		},
		{
			name:     "resource differing by trailing slash",
			token:    func(_ *Tokens, issued Issued) string { return issued.AccessToken },
			resource: testResource + "/",
			want:     ErrInvalidToken,
		},
		{
			name:     "empty token",
			token:    func(*Tokens, Issued) string { return "" },
			resource: testResource,
			want:     ErrInvalidToken,
		},
		{
			name:     "token with a control byte",
			token:    func(*Tokens, Issued) string { return "abc\ndef" },
			resource: testResource,
			want:     ErrInvalidToken,
		},
		{
			name:     "token beyond the length limit",
			token:    func(*Tokens, Issued) string { return strings.Repeat("a", maxTokenLength+1) },
			resource: testResource,
			want:     ErrInvalidToken,
		},
		{
			name:     "no resource to check against",
			token:    func(_ *Tokens, issued Issued) string { return issued.AccessToken },
			resource: "",
			want:     ErrUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newTestClock()
			tokens := NewTokens(WithClock(clock.Now))
			issued := tokens.Issue(testGrant())
			clock.Advance(tc.advance)

			_, err := tokens.Verify(t.Context(), tc.token(tokens, issued), tc.resource)
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify error = %v, want %v", err, tc.want)
			}
			if tc.want == ErrInvalidToken && errors.Is(err, ErrInsufficientScope) {
				t.Error("a rejected token must not also read as insufficiently scoped")
			}
		})
	}
}

func TestTokensRedeemRotates(t *testing.T) {
	clock := newTestClock()
	tokens := NewTokens(WithClock(clock.Now))
	grant := testGrant()
	first := tokens.Issue(grant)

	redeemed, err := tokens.Redeem(first.RefreshToken, grant.ClientID, nil)
	if err != nil {
		t.Fatalf("Redeem refused a fresh refresh token: %v", err)
	}
	if diff := cmp.Diff(grant, redeemed, cmpopts.IgnoreUnexported(Grant{})); diff != "" {
		t.Errorf("redeemed grant mismatch (-want +got):\n%s", diff)
	}
	if _, err := tokens.Redeem(first.RefreshToken, grant.ClientID, nil); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a refresh token was redeemed twice: %v", err)
	}

	second := tokens.Issue(redeemed)
	if _, err := tokens.Verify(t.Context(), first.AccessToken, testResource); err != nil {
		t.Errorf("the first access token stopped verifying after a refresh: %v", err)
	}
	if _, err := tokens.Verify(t.Context(), second.AccessToken, testResource); err != nil {
		t.Errorf("the second access token does not verify: %v", err)
	}
}

func TestTokensRedeemRefusals(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    func(issued Issued) string
		clientID string
		advance  time.Duration
	}{
		{
			name:     "another client",
			token:    func(issued Issued) string { return issued.RefreshToken },
			clientID: "https://other.example.com/client",
		},
		{
			name:     "expired refresh token",
			token:    func(issued Issued) string { return issued.RefreshToken },
			clientID: testGrant().ClientID,
			advance:  DefaultRefreshTokenTTL,
		},
		{
			name:     "access token as a refresh token",
			token:    func(issued Issued) string { return issued.AccessToken },
			clientID: testGrant().ClientID,
		},
		{
			name:     "malformed token",
			token:    func(Issued) string { return "not a token" },
			clientID: testGrant().ClientID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newTestClock()
			tokens := NewTokens(WithClock(clock.Now))
			issued := tokens.Issue(testGrant())
			clock.Advance(tc.advance)

			if _, err := tokens.Redeem(tc.token(issued), tc.clientID, nil); !errors.Is(err, ErrInvalidToken) {
				t.Errorf("Redeem = %v, want %v", err, ErrInvalidToken)
			}
		})
	}
}

// A refresh token presented by the wrong client is treated as leaked, so the
// rightful client cannot redeem it afterwards either.
func TestTokensRedeemByAnotherClientConsumesTheToken(t *testing.T) {
	tokens := NewTokens()
	grant := testGrant()
	issued := tokens.Issue(grant)

	if _, err := tokens.Redeem(issued.RefreshToken, "https://other.example.com/client", nil); err == nil {
		t.Fatal("Redeem accepted a token issued to another client")
	}
	if _, err := tokens.Redeem(issued.RefreshToken, grant.ClientID, nil); err == nil {
		t.Error("the rightful client redeemed a token another client had already presented")
	}
}

// A refusal the caller raises for the request's own parameters is not a leak,
// so the token stays redeemable once the request is corrected.
func TestTokensRedeemRefusedByCallerKeepsTheToken(t *testing.T) {
	tokens := NewTokens()
	grant := testGrant()
	issued := tokens.Issue(grant)
	refusal := errors.New("scope not granted")

	_, err := tokens.Redeem(issued.RefreshToken, grant.ClientID, func(Grant) error { return refusal })
	if !errors.Is(err, refusal) {
		t.Fatalf("Redeem = %v, want the caller's refusal", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Error("a caller's refusal must not read as an invalid token")
	}
	if _, err := tokens.Redeem(issued.RefreshToken, grant.ClientID, nil); err != nil {
		t.Errorf("the token was consumed by a refused request: %v", err)
	}
}

func TestTokensRevoke(t *testing.T) {
	tokens := NewTokens()
	grant := testGrant()
	issued := tokens.Issue(grant)
	tokens.Revoke(issued)

	if _, err := tokens.Verify(t.Context(), issued.AccessToken, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked access token verified: %v", err)
	}
	if _, err := tokens.Redeem(issued.RefreshToken, grant.ClientID, nil); err == nil {
		t.Error("revoked refresh token redeemed")
	}
	tokens.Revoke(Issued{AccessToken: "", RefreshToken: "not a token"})
}

// A code replay can arrive after the client has refreshed, so revoking what
// the code issued has to reach the pairs those refreshes rotated in, and must
// not touch another grant's tokens.
func TestTokensRevokeReachesRotatedTokens(t *testing.T) {
	tokens := NewTokens()
	grant := testGrant()
	first := tokens.Issue(grant)
	redeemed, err := tokens.Redeem(first.RefreshToken, grant.ClientID, nil)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	second := tokens.Issue(redeemed)
	other := tokens.Issue(grant)

	tokens.Revoke(first)

	for name, token := range map[string]string{"first": first.AccessToken, "rotated": second.AccessToken} {
		if _, err := tokens.Verify(t.Context(), token, testResource); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s access token survived revocation: %v", name, err)
		}
	}
	if _, err := tokens.Redeem(second.RefreshToken, grant.ClientID, nil); err == nil {
		t.Error("rotated refresh token survived revocation")
	}
	if _, err := tokens.Verify(t.Context(), other.AccessToken, testResource); err != nil {
		t.Errorf("another grant's access token was revoked: %v", err)
	}
	if _, err := tokens.Redeem(other.RefreshToken, grant.ClientID, nil); err != nil {
		t.Errorf("another grant's refresh token was revoked: %v", err)
	}
}

// The tables hold the grant for the token's remaining life and hand a copy to
// every caller, so a caller that reaches into a nested container would
// otherwise rewrite what the next request sees.
func TestTokensIsolateCallersFromTheTables(t *testing.T) {
	tokens := NewTokens()
	grant := testGrant()
	issued := tokens.Issue(grant)
	grant.Scopes[0] = "tampered"
	grant.Identity.Claims["name"] = "tampered"

	first, err := tokens.Verify(t.Context(), issued.AccessToken, testResource)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	first.Claims["groups"].([]any)[0] = "tampered"
	first.Claims["sub"] = "tampered"

	second, err := tokens.Verify(t.Context(), issued.AccessToken, testResource)
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	for claim, want := range map[string]any{
		"groups": []any{"admins"},
		"sub":    "12345",
		"name":   "A Person",
		"scope":  "openid email",
	} {
		if diff := cmp.Diff(want, second.Claims[claim]); diff != "" {
			t.Errorf("claim %q reached another caller's write (-want +got):\n%s", claim, diff)
		}
	}
}

func TestTokensStayBounded(t *testing.T) {
	tokens := NewTokens(withTableSizes(4, 2))
	var issued []Issued
	for range 10 {
		issued = append(issued, tokens.Issue(testGrant()))
	}
	if got := tokens.access.len(); got != 4 {
		t.Errorf("access table holds %d, want its bound of 4", got)
	}
	if got := tokens.refresh.len(); got != 2 {
		t.Errorf("refresh table holds %d, want its bound of 2", got)
	}
	if _, err := tokens.Verify(t.Context(), issued[0].AccessToken, testResource); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("the oldest access token survived eviction: %v", err)
	}
	if _, err := tokens.Verify(t.Context(), issued[9].AccessToken, testResource); err != nil {
		t.Errorf("the newest access token was evicted: %v", err)
	}
}

func TestTokenSyntax(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		valid bool
	}{
		{name: "base64url token", token: newToken(), valid: true},
		{name: "base64 with padding", token: "abc+/def==", valid: true},
		{name: "empty", token: ""},
		{name: "space", token: "abc def"},
		{name: "newline", token: "abc\ndef"},
		{name: "non ascii", token: "abcé"},
		{name: "quote", token: `abc"def`},
		{name: "at the length limit", token: strings.Repeat("a", maxTokenLength), valid: true},
		{name: "past the length limit", token: strings.Repeat("a", maxTokenLength+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenSyntax(tc.token)
			if tc.valid && err != nil {
				t.Errorf("validateTokenSyntax(%q) = %v, want nil", tc.token, err)
			}
			if !tc.valid && !errors.Is(err, ErrInvalidToken) {
				t.Errorf("validateTokenSyntax(%q) = %v, want %v", tc.token, err, ErrInvalidToken)
			}
			if err != nil && strings.Contains(err.Error(), tc.token) && tc.token != "" {
				t.Errorf("error %q echoes the token", err)
			}
		})
	}
}
