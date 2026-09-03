package cimd

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultCacheTTL is how long a document is reused when its origin
	// expresses no preference.
	DefaultCacheTTL = time.Hour
	// minCacheTTL and maxCacheTTL clamp what an origin asks for. The floor
	// keeps a hostile origin from making every authorization a fetch, and
	// the ceiling bounds how long a rotated redirect URI stays accepted.
	minCacheTTL = time.Minute
	maxCacheTTL = 24 * time.Hour
	// defaultCacheEntries bounds the cache. A distinct client is a distinct
	// origin someone chose to authorize, so the bound is a memory ceiling.
	defaultCacheEntries = 256
	// defaultMaxInflight bounds concurrent fetches across every client ID.
	// Concurrent callers for one client ID share a flight, so the bound is
	// hit only by distinct client IDs arriving faster than their origins
	// answer, which is what a tailnet peer flooding /authorize looks like.
	defaultMaxInflight = 16
	// fetchTimeout bounds one round trip, independent of the caller's
	// context, since a fetch is shared by every caller waiting on the same
	// client ID.
	fetchTimeout = 10 * time.Second
)

// Fetcher resolves client IDs to their metadata documents through a cache.
// It is safe for concurrent use, and concurrent callers for one client ID
// share a single fetch.
type Fetcher struct {
	client      *http.Client
	now         func() time.Time
	maxEntries  int
	maxInflight int

	mu       sync.Mutex
	cache    map[string]cached
	inflight map[string]*fetch
}

type cached struct {
	doc     *Document
	expires time.Time
}

// fetch is one in-flight retrieval its waiters share.
type fetch struct {
	done chan struct{}
	doc  *Document
	err  error
}

type Option func(*Fetcher)

// WithClock replaces the clock the cache expires by.
func WithClock(now func() time.Time) Option {
	return func(f *Fetcher) { f.now = now }
}

func withCacheEntries(n int) Option {
	return func(f *Fetcher) { f.maxEntries = n }
}

// withMaxInflight bounds concurrent fetches. Tests use it to exercise the
// bound.
func withMaxInflight(n int) Option {
	return func(f *Fetcher) { f.maxInflight = n }
}

// NewFetcher builds a Fetcher over client. The egress guard in NewClient is
// what makes fetching a stranger's URL safe in production, and tests inject
// a client for an origin they run. Redirects are refused whatever client is
// given, since the draft binds the document to the exact client_id URL.
func NewFetcher(client *http.Client, opts ...Option) *Fetcher {
	guarded := *client
	guarded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	f := &Fetcher{
		client:      &guarded,
		now:         time.Now,
		maxEntries:  defaultCacheEntries,
		maxInflight: defaultMaxInflight,
		cache:       make(map[string]cached),
		inflight:    make(map[string]*fetch),
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

// Fetch returns the metadata document for clientID, from the cache when it
// holds a live copy. Errors wrap ErrInvalidClientID, ErrInvalidDocument, or
// ErrFetch, and none of them is cached.
func (f *Fetcher) Fetch(ctx context.Context, clientID string) (*Document, error) {
	if _, err := ParseClientID(clientID); err != nil {
		return nil, err
	}

	f.mu.Lock()
	if entry, ok := f.cache[clientID]; ok && f.now().Before(entry.expires) {
		f.mu.Unlock()
		return entry.doc, nil
	}
	if in, ok := f.inflight[clientID]; ok {
		f.mu.Unlock()
		return in.wait(ctx)
	}
	if len(f.inflight) >= f.maxInflight {
		f.mu.Unlock()
		return nil, fmt.Errorf("%w: %d fetches already in flight", ErrFetch, f.maxInflight)
	}
	in := &fetch{done: make(chan struct{})}
	f.inflight[clientID] = in
	f.mu.Unlock()

	go f.run(clientID, in)
	return in.wait(ctx)
}

// wait blocks until the fetch completes or ctx ends. The fetch itself keeps
// running for the other waiters.
func (in *fetch) wait(ctx context.Context) (*Document, error) {
	select {
	case <-in.done:
		return in.doc, in.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: %v", ErrFetch, ctx.Err())
	}
}

// run performs the fetch its waiters share. It is detached from any caller's
// context, since the first caller giving up must not fail the others, and the
// fetch is bounded by its own timeout instead.
func (f *Fetcher) run(clientID string, in *fetch) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()

	doc, ttl, err := f.retrieve(ctx, clientID)

	f.mu.Lock()
	delete(f.inflight, clientID)
	if err == nil {
		f.store(clientID, doc, ttl)
	}
	f.mu.Unlock()

	in.doc, in.err = doc, err
	close(in.done)
}

// store caches doc for ttl, evicting the entry nearest expiry when full. It
// runs under f.mu.
func (f *Fetcher) store(clientID string, doc *Document, ttl time.Duration) {
	if f.maxEntries <= 0 {
		return
	}
	now := f.now()
	if _, ok := f.cache[clientID]; !ok {
		for len(f.cache) >= f.maxEntries {
			var victim string
			var soonest time.Time
			for id, entry := range f.cache {
				if victim == "" || entry.expires.Before(soonest) {
					victim, soonest = id, entry.expires
				}
			}
			delete(f.cache, victim)
		}
	}
	f.cache[clientID] = cached{doc: doc, expires: now.Add(ttl)}
}

func (f *Fetcher) retrieve(ctx context.Context, clientID string) (*Document, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "tailgate")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: %s answered %d", ErrFetch, clientID, resp.StatusCode)
	}
	if !isJSON(resp.Header.Get("Content-Type")) {
		return nil, 0, fmt.Errorf("%w: %s answered with %q rather than JSON", ErrFetch, clientID, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if len(body) > maxDocumentBytes {
		return nil, 0, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidDocument, maxDocumentBytes)
	}

	doc, err := parseDocument(clientID, body)
	if err != nil {
		return nil, 0, err
	}
	return doc, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// isJSON reports whether a Content-Type carries a JSON document, including
// the +json structured syntax suffix.
func isJSON(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

// cacheTTL reads the origin's cache directives and clamps what they ask for.
// An origin that asks for no caching still gets the floor: the draft has the
// server respect cache headers within its own bounds, and the floor is that
// bound.
func cacheTTL(cacheControl string) time.Duration {
	ttl := DefaultCacheTTL
	uncacheable := false
	for directive := range strings.SplitSeq(cacheControl, ",") {
		name, value, _ := strings.Cut(strings.TrimSpace(directive), "=")
		switch strings.ToLower(name) {
		case "no-store", "no-cache":
			uncacheable = true
		case "max-age":
			if seconds, err := strconv.Atoi(strings.Trim(value, `"`)); err == nil {
				ttl = time.Duration(seconds) * time.Second
			}
		}
	}
	if uncacheable {
		ttl = minCacheTTL
	}
	return min(max(ttl, minCacheTTL), maxCacheTTL)
}
