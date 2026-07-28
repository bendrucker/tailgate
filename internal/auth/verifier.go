package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
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

var (
	// ErrInvalidToken means the bearer failed verification: absent, inactive,
	// expired, or not issued for the requested resource. Handlers map it to
	// 401 with a WWW-Authenticate challenge.
	ErrInvalidToken = errors.New("auth: invalid token")
	// ErrUnavailable means verification could not run at all: the caller's
	// token may be fine, tailgate just cannot prove it. Handlers map it to
	// 503, never to a 401 challenge and never to an allow.
	ErrUnavailable = errors.New("auth: verification unavailable")
)

const (
	// defaultCacheTTL caps how long a verified token is served from cache.
	// tsidp access tokens live five minutes, so a longer ceiling would only
	// widen the window in which a revoked client keeps working.
	defaultCacheTTL  = 5 * time.Minute
	defaultCacheSize = 1024
	// defaultNegativeCacheTTL keeps a rejected token cheap to re-reject without
	// pinning the rejection past a plausible re-issue of the same string.
	defaultNegativeCacheTTL  = 30 * time.Second
	defaultNegativeCacheSize = 4096
	// defaultIntrospectionConcurrency bounds simultaneous calls to tsidp, whose
	// token store is a mutex-guarded map.
	defaultIntrospectionConcurrency = 64
	defaultIntrospectionTimeout     = 10 * time.Second
	// maxTokenLength is far above tsidp's 32 hex characters and far below what
	// is worth forwarding.
	maxTokenLength = 512
)

// Verifier validates bearer tokens by introspecting them against the issuer.
// It is safe for concurrent use.
type Verifier struct {
	client        *http.Client
	introspectURL string
	now           func() time.Time

	active      *tokenCache[map[string]any]
	inactive    *tokenCache[struct{}]
	ttl         time.Duration
	negativeTTL time.Duration
	timeout     time.Duration
	slots       chan struct{}
	inflight    *inflightGroup
}

// VerifierOption adjusts the introspection path's caching and abuse controls.
type VerifierOption func(*verifierOptions)

type verifierOptions struct {
	cacheSize         int
	cacheTTL          time.Duration
	negativeCacheSize int
	negativeCacheTTL  time.Duration
	concurrency       int
	timeout           time.Duration
	now               func() time.Time
}

// WithCacheSize bounds how many verified tokens are held in memory. Zero or
// less disables the cache, making every request an introspection round trip.
func WithCacheSize(n int) VerifierOption {
	return func(o *verifierOptions) { o.cacheSize = n }
}

// WithCacheTTL caps how long a verified token's claims are reused. An entry
// never outlives the token's own exp regardless of this value, so raising it
// past the issuer's token lifetime has no effect. The effective value is the
// staleness window: a token revoked at tsidp keeps working until its cached
// claims lapse.
func WithCacheTTL(d time.Duration) VerifierOption {
	return func(o *verifierOptions) { o.cacheTTL = d }
}

// WithNegativeCacheSize bounds how many rejected tokens are remembered. Zero or
// less disables the negative cache. The bound matters more than the size: these
// entries are keyed by attacker-chosen strings.
func WithNegativeCacheSize(n int) VerifierOption {
	return func(o *verifierOptions) { o.negativeCacheSize = n }
}

// WithNegativeCacheTTL sets how long a token the issuer reported inactive is
// re-rejected without asking again. Zero or less disables the negative cache.
// Only inactive verdicts are cached this way; a failure to reach the issuer
// stays retryable.
func WithNegativeCacheTTL(d time.Duration) VerifierOption {
	return func(o *verifierOptions) { o.negativeCacheTTL = d }
}

// WithIntrospectionConcurrency bounds simultaneous introspection calls. Once
// the bound is reached, further calls are shed as ErrUnavailable rather than
// queued. Zero or less removes the bound.
func WithIntrospectionConcurrency(n int) VerifierOption {
	return func(o *verifierOptions) { o.concurrency = n }
}

// WithIntrospectionTimeout bounds a single introspection call, which bounds how
// long a stalled issuer can hold a concurrency slot.
func WithIntrospectionTimeout(d time.Duration) VerifierOption {
	return func(o *verifierOptions) { o.timeout = d }
}

// WithClock replaces the clock used for expiry and cache lifetimes.
func WithClock(now func() time.Time) VerifierOption {
	return func(o *verifierOptions) { o.now = now }
}

func newVerifierOptions(opts []VerifierOption) verifierOptions {
	o := verifierOptions{
		cacheSize:         defaultCacheSize,
		cacheTTL:          defaultCacheTTL,
		negativeCacheSize: defaultNegativeCacheSize,
		negativeCacheTTL:  defaultNegativeCacheTTL,
		concurrency:       defaultIntrospectionConcurrency,
		timeout:           defaultIntrospectionTimeout,
		now:               time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.timeout <= 0 {
		o.timeout = defaultIntrospectionTimeout
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o
}

// NewVerifier discovers the issuer's introspection endpoint from its OIDC
// metadata. client must reach the issuer with an identity it trusts for
// introspection. For tsidp that means dialing over the tailnet. Construction
// failure means no request can be verified, so callers must treat it as the
// service being unavailable rather than skipping verification.
func NewVerifier(ctx context.Context, client *http.Client, issuer string, opts ...VerifierOption) (*Verifier, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: parse issuer: %w", err)
	}
	wellKnown, err := url.JoinPath(issuer, ".well-known", "openid-configuration")
	if err != nil {
		return nil, fmt.Errorf("auth: discovery URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery request: %w", err)
	}
	var doc struct {
		Issuer                string `json:"issuer"`
		IntrospectionEndpoint string `json:"introspection_endpoint"`
	}
	if err := fetchJSON(client, req, &doc); err != nil {
		return nil, fmt.Errorf("auth: discovery: %w", err)
	}
	if doc.Issuer != issuer {
		return nil, fmt.Errorf("auth: discovery: issuer mismatch: got %q, want %q", doc.Issuer, issuer)
	}
	if doc.IntrospectionEndpoint == "" {
		return nil, fmt.Errorf("auth: discovery: issuer advertises no introspection endpoint")
	}
	// Every bearer token is forwarded to this endpoint, so an off-origin
	// value in a tampered discovery document would exfiltrate live tokens.
	introspect, err := url.Parse(doc.IntrospectionEndpoint)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery: parse introspection endpoint: %w", err)
	}
	if introspect.Scheme != issuerURL.Scheme || introspect.Host != issuerURL.Host {
		return nil, fmt.Errorf("auth: discovery: introspection endpoint %q is not on issuer origin %q", doc.IntrospectionEndpoint, issuer)
	}

	o := newVerifierOptions(opts)
	v := &Verifier{
		client:        client,
		introspectURL: doc.IntrospectionEndpoint,
		now:           o.now,
		active:        newTokenCache[map[string]any](o.cacheSize),
		inactive:      newTokenCache[struct{}](o.negativeCacheSize),
		ttl:           o.cacheTTL,
		negativeTTL:   o.negativeCacheTTL,
		timeout:       o.timeout,
		inflight:      &inflightGroup{},
	}
	if o.concurrency > 0 {
		v.slots = make(chan struct{}, o.concurrency)
	}
	return v, nil
}

// Verify introspects the bearer token and returns the caller's identity if the
// token is active, unexpired, and audience-bound to resource. The resource
// string must come from resource.URLs so the audience comparison is byte-exact
// against what the client requested and tsidp granted.
//
// Any verification failure returns ErrInvalidToken. Failure to complete
// introspection at all, including load shed by the abuse controls, returns
// ErrUnavailable instead, so handlers can answer 503 rather than challenging
// the client to re-authenticate.
func (v *Verifier) Verify(ctx context.Context, token, resource string) (Identity, error) {
	if err := validateTokenSyntax(token); err != nil {
		return Identity{}, err
	}
	if resource == "" {
		return Identity{}, fmt.Errorf("%w: no audience to check the token against", ErrUnavailable)
	}

	claims, err := v.introspect(ctx, token)
	if err != nil {
		return Identity{}, err
	}
	return v.identityFromClaims(claims, resource)
}

// identityFromClaims applies the checks that depend on the request rather than
// on the token alone, so they run on every Verify including cache hits.
func (v *Verifier) identityFromClaims(claims map[string]any, resource string) (Identity, error) {
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
	return Identity{Subject: sub, Email: email, Claims: cloneClaims(claims)}, nil
}

// fetchJSON runs the request and decodes a 200 JSON response into v, holding
// the response-handling policy (status acceptance, content type, 1 MiB body
// cap) in one place for discovery and introspection.
func fetchJSON(client *http.Client, req *http.Request, v any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	// tsidp labels both discovery and introspection application/json. Anything
	// else means the response came from something other than the endpoint
	// tailgate meant to reach, such as an interposed error page.
	contentType := resp.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || !isJSONMediaType(mediaType) {
		return fmt.Errorf("unexpected content type %q", contentType)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

func isJSONMediaType(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// cloneClaims deep-copies a decoded claim set. The cache holds the original for
// the token's remaining life and hands it to every concurrent caller, so a
// shallow copy would leave the nested containers JSON decoding produces, such
// as the aud slice, shared across requests.
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
