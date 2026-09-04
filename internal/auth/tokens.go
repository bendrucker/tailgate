package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/bendrucker/tailgate/internal/resource"
)

var (
	// ErrInvalidToken means the bearer failed verification: absent, unknown,
	// expired, or not issued for the requested resource. Handlers map it to
	// 401 with a WWW-Authenticate challenge.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrInsufficientScope means the token verified but was not granted a scope
	// tailgate requires. RFC 6750 section 3.1 answers it with 403: the
	// credential is good, and re-authenticating under the same grant yields
	// the same token. It deliberately does not wrap ErrInvalidToken: a
	// handler that tested for the wrapped sentinel first would answer 401 to
	// an insufficiently scoped token.
	ErrInsufficientScope = errors.New("auth: insufficient scope")
	// ErrUnavailable means verification could not run at all: the caller's
	// token may be fine, tailgate just cannot prove it. Handlers map it to
	// 503, never to a 401 challenge and never to an allow.
	ErrUnavailable = errors.New("auth: verification unavailable")
)

const (
	// DefaultAccessTokenTTL is how long an access token verifies. Revocation
	// is a restart, so the lifetime is the window a client keeps working
	// after being cut off by any other means.
	DefaultAccessTokenTTL = time.Hour
	// DefaultRefreshTokenTTL is how long a refresh token can be redeemed. Each
	// redemption rotates it, so the lifetime bounds an idle client.
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	// defaultAccessTokens and defaultRefreshTokens bound the tables. Both are
	// filled only by grants a person approved, so the bound is a memory
	// ceiling.
	defaultAccessTokens  = 16384
	defaultRefreshTokens = 16384
	// tokenBytes is the entropy behind every token. 32 bytes is 256 bits,
	// which encodes to 43 base64url characters.
	tokenBytes = 32
	// maxTokenLength is far above the 43 characters tailgate mints and far
	// below what is worth hashing.
	maxTokenLength = 512
)

// Grant is the unit both token kinds carry, so a refresh reissues exactly what
// was approved.
type Grant struct {
	Identity Identity
	// ClientID is the CIMD client identifier the grant was approved for. A
	// refresh token is bound to it.
	ClientID string
	// Resource is the audience, minted by resource.URLs, and the only resource
	// the access token verifies against.
	Resource string
	Scopes   []string
	// family names every token pair descended from one authorization code,
	// through any number of refreshes. Issue mints it for a grant that has
	// none, and a redeemed grant carries it forward, so revoking a family
	// reaches the pairs a refresh rotated in after the code was redeemed.
	family string
}

type Issued struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    time.Duration
	family       string
}

// grantEntry is what a token digest resolves to.
type grantEntry struct {
	grant   Grant
	issued  time.Time
	expires time.Time
}

// Tokens issues and verifies tailgate's own opaque bearer tokens from memory.
// A token is 32 random bytes, and the tables key on its SHA-256 digest so a
// heap dump cannot yield usable credentials. Nothing persists: a restart
// invalidates every token, and clients recover through the ordinary 401
// challenge. It is safe for concurrent use.
type Tokens struct {
	now        func() time.Time
	accessTTL  time.Duration
	refreshTTL time.Duration
	required   []string
	access     *tokenCache[grantEntry]
	refresh    *tokenCache[grantEntry]
}

type TokensOption func(*tokensOptions)

type tokensOptions struct {
	now           func() time.Time
	accessTTL     time.Duration
	refreshTTL    time.Duration
	accessTokens  int
	refreshTokens int
}

// WithClock replaces the clock used for issue and expiry.
func WithClock(now func() time.Time) TokensOption {
	return func(o *tokensOptions) { o.now = now }
}

func WithAccessTokenTTL(d time.Duration) TokensOption {
	return func(o *tokensOptions) { o.accessTTL = d }
}

func WithRefreshTokenTTL(d time.Duration) TokensOption {
	return func(o *tokensOptions) { o.refreshTTL = d }
}

// withTableSizes bounds the two tables. Tests use it to exercise eviction.
func withTableSizes(access, refresh int) TokensOption {
	return func(o *tokensOptions) { o.accessTokens, o.refreshTokens = access, refresh }
}

func NewTokens(opts ...TokensOption) *Tokens {
	o := tokensOptions{
		now:           time.Now,
		accessTTL:     DefaultAccessTokenTTL,
		refreshTTL:    DefaultRefreshTokenTTL,
		accessTokens:  defaultAccessTokens,
		refreshTokens: defaultRefreshTokens,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.accessTTL <= 0 {
		o.accessTTL = DefaultAccessTokenTTL
	}
	if o.refreshTTL <= 0 {
		o.refreshTTL = DefaultRefreshTokenTTL
	}
	return &Tokens{
		now:        o.now,
		accessTTL:  o.accessTTL,
		refreshTTL: o.refreshTTL,
		required:   resource.RequiredScopes(),
		access:     newTokenCache[grantEntry](o.accessTokens),
		refresh:    newTokenCache[grantEntry](o.refreshTokens),
	}
}

// Issue mints an access and refresh token pair for g. The grant is copied, so
// the caller's slices and claim map stay its own.
func (t *Tokens) Issue(g Grant) Issued {
	now := t.now()
	if g.family == "" {
		g.family = newToken()
	}
	entry := grantEntry{grant: cloneGrant(g), issued: now, expires: now.Add(t.accessTTL)}
	access := newToken()
	t.access.put(tokenDigest(access), entry, entry.expires, now)

	entry.expires = now.Add(t.refreshTTL)
	refresh := newToken()
	t.refresh.put(tokenDigest(refresh), entry, entry.expires, now)

	return Issued{AccessToken: access, RefreshToken: refresh, ExpiresIn: t.accessTTL, family: g.family}
}

// Redeem consumes a refresh token and returns the grant it carried, so the
// caller can Issue a fresh pair. The token is single use: a second redemption
// finds nothing. A token presented by a client other than the one it was
// issued to is consumed and refused, since RFC 6749 section 10.4 treats that
// as a leaked token.
//
// accept, when not nil, sees the grant before the token is consumed. An error
// from it is returned as is and leaves the token in place, so a request the
// caller refuses for its own parameters can be corrected and retried. Every
// other refusal wraps ErrInvalidToken.
func (t *Tokens) Redeem(refreshToken, clientID string, accept func(Grant) error) (Grant, error) {
	if err := validateTokenSyntax(refreshToken); err != nil {
		return Grant{}, err
	}
	var refused error
	entry, ok := t.refresh.take(tokenDigest(refreshToken), t.now(), func(e grantEntry) bool {
		if e.grant.ClientID != clientID {
			return true
		}
		if accept != nil {
			refused = accept(cloneGrant(e.grant))
		}
		return refused == nil
	})
	if refused != nil {
		return Grant{}, refused
	}
	if !ok || entry.grant.ClientID != clientID {
		return Grant{}, fmt.Errorf("%w: unknown, expired, already used, or another client's", ErrInvalidToken)
	}
	return entry.grant, nil
}

// Revoke forgets every token descended from the same grant as issued,
// including the pairs later refreshes rotated in. The authorization server
// calls it when a code is replayed, which RFC 6749 section 4.1.2 answers by
// revoking what the first redemption issued. An Issued that did not come from
// Issue names no family and revokes nothing.
func (t *Tokens) Revoke(issued Issued) {
	if issued.family == "" {
		return
	}
	sameFamily := func(e grantEntry) bool { return e.grant.family == issued.family }
	t.access.deleteWhere(sameFamily)
	t.refresh.deleteWhere(sameFamily)
}

// Verify returns the caller's identity if token is a live access token issued
// for resourceURL. The resource string must come from resource.URLs so the
// audience comparison is byte-exact against what the client requested and
// the person approved.
//
// Any verification failure returns ErrInvalidToken, except a token granted
// without a scope tailgate requires, which returns ErrInsufficientScope. A
// call with no resource to check against returns ErrUnavailable, since that
// is a wiring fault rather than a bad credential.
func (t *Tokens) Verify(_ context.Context, token, resourceURL string) (Identity, error) {
	if err := validateTokenSyntax(token); err != nil {
		return Identity{}, err
	}
	if resourceURL == "" {
		return Identity{}, fmt.Errorf("%w: no audience to check the token against", ErrUnavailable)
	}
	entry, ok := t.access.get(tokenDigest(token), t.now())
	if !ok {
		return Identity{}, fmt.Errorf("%w: unknown or expired", ErrInvalidToken)
	}
	if entry.grant.Resource != resourceURL {
		return Identity{}, fmt.Errorf("%w: audience does not include %s", ErrInvalidToken, resourceURL)
	}
	if missing := missingScopes(entry.grant.Scopes, t.required); len(missing) > 0 {
		return Identity{}, fmt.Errorf("%w: token was not granted %s", ErrInsufficientScope, strings.Join(missing, " "))
	}
	return entry.identity(), nil
}

// identity builds the caller's identity from the grant. The claim set is
// rebuilt per call from the stored grant, so policy can match on any of it
// and no request shares a map with another.
func (e grantEntry) identity() Identity {
	claims := cloneClaims(e.grant.Identity.Claims)
	claims["sub"] = e.grant.Identity.Subject
	if e.grant.Identity.Email != "" {
		claims["email"] = e.grant.Identity.Email
	}
	claims["scope"] = strings.Join(e.grant.Scopes, " ")
	claims["client_id"] = e.grant.ClientID
	claims["aud"] = e.grant.Resource
	claims["iat"] = e.issued.Unix()
	claims["exp"] = e.expires.Unix()
	return Identity{Subject: e.grant.Identity.Subject, Email: e.grant.Identity.Email, Claims: claims}
}

func cloneGrant(g Grant) Grant {
	g.Identity.Claims = cloneClaims(g.Identity.Claims)
	g.Scopes = slices.Clone(g.Scopes)
	return g
}

// cloneClaims deep-copies a claim set. The tables hold the original for the
// token's remaining life and hand a copy to every caller, so nested
// containers are never shared across requests.
func cloneClaims(claims map[string]any) map[string]any {
	cloned := make(map[string]any, len(claims))
	for name, value := range claims {
		cloned[name] = cloneClaimValue(value)
	}
	return cloned
}

func cloneClaimValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		return cloneClaims(v)
	case []any:
		cloned := make([]any, len(v))
		for i, element := range v {
			cloned[i] = cloneClaimValue(element)
		}
		return cloned
	default:
		return v
	}
}

func missingScopes(granted, required []string) []string {
	var missing []string
	for _, scope := range required {
		if !slices.Contains(granted, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

// newToken returns a fresh random token. crypto/rand.Read cannot fail on the
// platforms Go supports, so there is no error to propagate.
func newToken() string {
	raw := make([]byte, tokenBytes)
	rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// tokenDigest keys the tables by a hash, so a heap dump or a map iteration
// cannot yield usable credentials.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return string(sum[:])
}

// validateTokenSyntax rejects bearers that cannot be tailgate tokens before
// they are hashed. The grammar is RFC 6750 b64token, which excludes the CR,
// LF, and non-ASCII bytes a caller might use to smuggle content into
// tailgate's logs. Errors quote the offending offset and never the token.
func validateTokenSyntax(token string) error {
	if token == "" {
		return fmt.Errorf("%w: empty", ErrInvalidToken)
	}
	if len(token) > maxTokenLength {
		return fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrInvalidToken, len(token), maxTokenLength)
	}
	for i := 0; i < len(token); i++ {
		if !isTokenByte(token[i]) {
			return fmt.Errorf("%w: illegal byte at offset %d", ErrInvalidToken, i)
		}
	}
	return nil
}

func isTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~+/=", c) >= 0
}
