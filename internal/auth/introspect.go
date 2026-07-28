package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Introspection runs before any authentication, so every token an internet
// client sprays at the Funnel endpoint would otherwise cost tsidp a round trip.
// The path in this file is the load-bearing defense: reject malformed bearers
// without asking tsidp, answer repeats from bounded caches, collapse concurrent
// lookups of one token into a single call, and shed load past a fixed number of
// concurrent calls. Every limit denies rather than admits when it trips.

// introspect returns the claim set tsidp reports for token, from cache when it
// can. A token tsidp reports as inactive returns ErrInvalidToken; a lookup that
// could not be completed returns ErrUnavailable so the caller answers 503
// instead of challenging a possibly-valid client.
func (v *Verifier) introspect(ctx context.Context, token string) (map[string]any, error) {
	key := tokenDigest(token)
	now := v.now()
	if claims, ok := v.active.get(key, now); ok {
		return claims, nil
	}
	if _, ok := v.inactive.get(key, now); ok {
		return nil, fmt.Errorf("%w: not active", ErrInvalidToken)
	}
	return v.inflight.do(ctx, key, func(ctx context.Context) (map[string]any, error) {
		return v.introspectUncached(ctx, token, key)
	})
}

func (v *Verifier) introspectUncached(ctx context.Context, token, key string) (map[string]any, error) {
	release, ok := v.acquireSlot()
	if !ok {
		return nil, fmt.Errorf("%w: introspection concurrency limit reached", ErrUnavailable)
	}
	defer release()

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.introspectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("%w: introspection request: %w", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var claims map[string]any
	if err := fetchJSON(v.client, req, &claims); err != nil {
		return nil, fmt.Errorf("%w: introspect: %w", ErrUnavailable, err)
	}

	now := v.now()
	if active, ok := claims["active"].(bool); !ok || !active {
		v.inactive.put(key, struct{}{}, now.Add(v.negativeTTL), now)
		return nil, fmt.Errorf("%w: not active", ErrInvalidToken)
	}
	// An active answer carrying no exp is unusable and has no sound TTL to be
	// cached under, so it is denied here rather than left to Verify. Denying it
	// here is what keeps it out of the uncached path, where it would cost tsidp a
	// round trip on every request that presents it.
	exp, ok := numericClaim(claims, "exp")
	if !ok {
		v.inactive.put(key, struct{}{}, now.Add(v.negativeTTL), now)
		return nil, fmt.Errorf("%w: missing exp", ErrInvalidToken)
	}
	// Claims are cached before the audience and expiry checks because they
	// describe the token, not the request: one token presented to two upstreams
	// is one introspection. Every Verify re-runs those checks against the
	// cached claims, so a cache hit can never widen what the token authorizes.
	v.active.put(key, claims, cacheUntil(time.Unix(exp, 0), now.Add(v.ttl)), now)
	return claims, nil
}

// cacheUntil bounds a cached allow by the token's own expiry and by the
// configured ceiling, whichever comes first. The ceiling is the documented
// staleness window: revoking a client at tsidp takes effect for tailgate only
// after the cached entry lapses.
func cacheUntil(exp, ceiling time.Time) time.Time {
	if exp.Before(ceiling) {
		return exp
	}
	return ceiling
}

// acquireSlot takes one of the concurrent introspection slots without waiting.
// Queueing would let a spray of distinct tokens pile up goroutines and
// connections against tsidp, so an overflowing gate sheds the request instead.
func (v *Verifier) acquireSlot() (func(), bool) {
	if v.slots == nil {
		return func() {}, true
	}
	select {
	case v.slots <- struct{}{}:
		return func() { <-v.slots }, true
	default:
		return nil, false
	}
}

// tokenDigest keys caches and in-flight calls by a hash rather than the bearer
// itself, so a heap dump or a map iteration cannot yield usable credentials.
func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return string(sum[:])
}

// validateTokenSyntax rejects bearers that cannot be tsidp tokens, before they
// cost an introspection round trip. The grammar is RFC 6750 b64token, which
// excludes the CR, LF, and non-ASCII bytes a caller might use to smuggle
// content into the introspection request or into tailgate's logs. Errors quote
// the offending offset and never the token.
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

// inflightGroup collapses concurrent lookups of one token digest into a single
// introspection call.
type inflightGroup struct {
	mu    sync.Mutex
	calls map[string]*inflightCall
}

type inflightCall struct {
	done   chan struct{}
	claims map[string]any
	err    error
}

// do runs fn for key unless an identical call is already running, in which case
// it waits for that one. fn runs on a context detached from any single caller,
// so one caller giving up neither cancels the shared call nor denies the
// others. A caller whose own context ends first gets ErrUnavailable: tailgate
// did not learn whether the token is good, which is not grounds to challenge.
func (g *inflightGroup) do(ctx context.Context, key string, fn func(context.Context) (map[string]any, error)) (map[string]any, error) {
	g.mu.Lock()
	call, running := g.calls[key]
	if !running {
		call = &inflightCall{done: make(chan struct{})}
		if g.calls == nil {
			g.calls = make(map[string]*inflightCall)
		}
		g.calls[key] = call
		detached := context.WithoutCancel(ctx)
		go func() {
			call.claims, call.err = fn(detached)
			g.mu.Lock()
			delete(g.calls, key)
			g.mu.Unlock()
			close(call.done)
		}()
	}
	g.mu.Unlock()

	select {
	case <-call.done:
		return call.claims, call.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: introspect: %w", ErrUnavailable, ctx.Err())
	}
}
