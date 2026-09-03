package cimd

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// origin is a client's metadata host under test control. Its client ID is
// its own URL, so documents it serves validate against it.
type origin struct {
	server *httptest.Server
	mu     sync.Mutex
	handle http.HandlerFunc
	hits   atomic.Int32
}

func newOrigin(t *testing.T) *origin {
	t.Helper()
	o := &origin{}
	o.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.hits.Add(1)
		o.mu.Lock()
		handle := o.handle
		o.mu.Unlock()
		handle(w, r)
	}))
	t.Cleanup(o.server.Close)
	o.serveDocument(nil)
	return o
}

func (o *origin) clientID() string { return o.server.URL + "/oauth/client" }

func (o *origin) serveDocument(headers map[string]string) {
	o.serve(func(w http.ResponseWriter, _ *http.Request) {
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"` + o.clientID() + `","client_name":"Test Client","redirect_uris":["https://client.example.com/callback"]}`))
	})
}

func (o *origin) serve(handle http.HandlerFunc) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.handle = handle
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newFetcher(t *testing.T, o *origin, opts ...Option) (*Fetcher, *clock) {
	t.Helper()
	c := &clock{now: time.Unix(1_800_000_000, 0)}
	return NewFetcher(o.server.Client(), append([]Option{WithClock(c.Now)}, opts...)...), c
}

func TestFetchCachesByMaxAge(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cacheControl string
		fresh        time.Duration
		stale        time.Duration
	}{
		{name: "no cache header", fresh: DefaultCacheTTL - time.Second, stale: DefaultCacheTTL},
		{name: "max-age within bounds", cacheControl: "max-age=600", fresh: 599 * time.Second, stale: 600 * time.Second},
		{name: "max-age below the floor", cacheControl: "max-age=1", fresh: minCacheTTL - time.Second, stale: minCacheTTL},
		{name: "no-store still gets the floor", cacheControl: "no-store", fresh: minCacheTTL - time.Second, stale: minCacheTTL},
		{name: "max-age above the ceiling", cacheControl: "public, max-age=999999", fresh: maxCacheTTL - time.Second, stale: maxCacheTTL},
		{name: "quoted max-age", cacheControl: `max-age="120"`, fresh: 119 * time.Second, stale: 120 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOrigin(t)
			if tc.cacheControl != "" {
				o.serveDocument(map[string]string{"Cache-Control": tc.cacheControl})
			}
			fetcher, c := newFetcher(t, o)

			first, err := fetcher.Fetch(t.Context(), o.clientID())
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if first.ClientName != "Test Client" {
				t.Errorf("client_name = %q, want %q", first.ClientName, "Test Client")
			}

			c.Advance(tc.fresh)
			if _, err := fetcher.Fetch(t.Context(), o.clientID()); err != nil {
				t.Fatalf("Fetch while fresh: %v", err)
			}
			if got := o.hits.Load(); got != 1 {
				t.Errorf("origin fetched %d times while the document was fresh, want 1", got)
			}

			c.Advance(tc.stale - tc.fresh)
			if _, err := fetcher.Fetch(t.Context(), o.clientID()); err != nil {
				t.Fatalf("Fetch once stale: %v", err)
			}
			if got := o.hits.Load(); got != 2 {
				t.Errorf("origin fetched %d times after the document went stale, want 2", got)
			}
		})
	}
}

func TestFetchRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		serve  http.HandlerFunc
		want   error
		reason string
	}{
		{
			name: "not found",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				http.NotFound(w, nil)
			},
			want:   ErrFetch,
			reason: "answered 404",
		},
		{
			name: "redirect",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://elsewhere.example.com/client")
				w.WriteHeader(http.StatusFound)
			},
			want:   ErrFetch,
			reason: "answered 302",
		},
		{
			name: "html",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.Write([]byte(`{"client_id":"x"}`))
			},
			want:   ErrFetch,
			reason: "rather than JSON",
		},
		{
			name: "oversized",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"client_id":"` + strings.Repeat("a", maxDocumentBytes) + `"}`))
			},
			want:   ErrInvalidDocument,
			reason: "exceeds",
		},
		{
			name: "wrong client id",
			serve: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"client_id":"https://other.example.com/client","redirect_uris":["https://x.example.com/cb"]}`))
			},
			want:   ErrInvalidDocument,
			reason: "client_id does not match",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := newOrigin(t)
			o.serve(tc.serve)
			fetcher, _ := newFetcher(t, o)

			_, err := fetcher.Fetch(t.Context(), o.clientID())
			if !errors.Is(err, tc.want) {
				t.Fatalf("Fetch error = %v, want %v", err, tc.want)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("error %q does not name %q", err, tc.reason)
			}

			o.serveDocument(nil)
			if _, err := fetcher.Fetch(t.Context(), o.clientID()); err != nil {
				t.Errorf("a failure was cached: %v", err)
			}
		})
	}
}

func TestFetchRefusesAnInvalidClientIDWithoutFetching(t *testing.T) {
	o := newOrigin(t)
	fetcher, _ := newFetcher(t, o)
	_, err := fetcher.Fetch(t.Context(), "http://example.com/client")
	if !errors.Is(err, ErrInvalidClientID) {
		t.Fatalf("Fetch error = %v, want %v", err, ErrInvalidClientID)
	}
	if got := o.hits.Load(); got != 0 {
		t.Errorf("origin fetched %d times for an invalid client ID", got)
	}
}

func TestFetchSharesOneFlight(t *testing.T) {
	o := newOrigin(t)
	release := make(chan struct{})
	o.serve(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"` + o.clientID() + `","redirect_uris":["https://client.example.com/callback"]}`))
	})
	fetcher, _ := newFetcher(t, o)

	const callers = 8
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := fetcher.Fetch(context.Background(), o.clientID())
			errs <- err
		}()
	}
	// Every caller has to be waiting before the origin answers for the flight
	// to be shared, and the fetcher exposes nothing to wait on, so this waits
	// for the origin to have been asked and then a little longer.
	deadline := time.Now().Add(2 * time.Second)
	for o.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)

	for range callers {
		if err := <-errs; err != nil {
			t.Errorf("Fetch: %v", err)
		}
	}
	if got := o.hits.Load(); got != 1 {
		t.Errorf("origin fetched %d times for %d concurrent callers, want 1", got, callers)
	}
}

// Distinct client IDs do not share a flight, so the bound across them is what
// keeps a flood of unique client_id values from holding open unbounded
// connections to the origins they name.
func TestFetchBoundsFlightsAcrossClients(t *testing.T) {
	o := newOrigin(t)
	release := make(chan struct{})
	o.serve(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"` + o.clientID() + `","redirect_uris":["https://client.example.com/callback"]}`))
	})
	fetcher, _ := newFetcher(t, o, withMaxInflight(1))

	first := make(chan error, 1)
	go func() {
		_, err := fetcher.Fetch(context.Background(), o.clientID())
		first <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for o.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := fetcher.Fetch(t.Context(), o.clientID()+"-other"); !errors.Is(err, ErrFetch) {
		t.Errorf("Fetch past the in-flight bound = %v, want %v", err, ErrFetch)
	}
	if got := o.hits.Load(); got != 1 {
		t.Errorf("origin fetched %d times, want 1: the refused fetch must not reach it", got)
	}

	close(release)
	if err := <-first; err != nil {
		t.Errorf("the fetch within the bound: %v", err)
	}
	if _, err := fetcher.Fetch(t.Context(), o.clientID()+"-other"); errors.Is(err, ErrFetch) && strings.Contains(err.Error(), "in flight") {
		t.Errorf("a completed flight still counted against the bound: %v", err)
	}
}

func TestFetchCallerCancellation(t *testing.T) {
	o := newOrigin(t)
	release := make(chan struct{})
	o.serve(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"` + o.clientID() + `","redirect_uris":["https://client.example.com/callback"]}`))
	})
	fetcher, _ := newFetcher(t, o)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := fetcher.Fetch(ctx, o.clientID()); !errors.Is(err, ErrFetch) {
		t.Fatalf("Fetch with a canceled context = %v, want %v", err, ErrFetch)
	}

	// The flight the canceled caller started still completes for the next
	// caller, which shares it.
	close(release)
	if _, err := fetcher.Fetch(t.Context(), o.clientID()); err != nil {
		t.Fatalf("Fetch after a canceled caller: %v", err)
	}
	if got := o.hits.Load(); got != 1 {
		t.Errorf("origin fetched %d times, want 1", got)
	}
}

func TestFetchCacheStaysBounded(t *testing.T) {
	o := newOrigin(t)
	o.serve(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"client_id":"` + o.server.URL + r.URL.Path + `","redirect_uris":["https://client.example.com/callback"]}`))
	})
	fetcher, _ := newFetcher(t, o, withCacheEntries(3))

	for _, path := range []string{"/a", "/b", "/c", "/d", "/e"} {
		if _, err := fetcher.Fetch(t.Context(), o.server.URL+path); err != nil {
			t.Fatalf("Fetch %s: %v", path, err)
		}
	}
	fetcher.mu.Lock()
	size := len(fetcher.cache)
	fetcher.mu.Unlock()
	if size != 3 {
		t.Errorf("cache holds %d documents, want its bound of 3", size)
	}
}

func TestIsJSON(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		want        bool
	}{
		{name: "application json", contentType: "application/json", want: true},
		{name: "with charset", contentType: "application/json; charset=utf-8", want: true},
		{name: "structured suffix", contentType: "application/cimd+json", want: true},
		{name: "text", contentType: "text/plain"},
		{name: "html", contentType: "text/html; charset=utf-8"},
		{name: "empty", contentType: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isJSON(tc.contentType); got != tc.want {
				t.Errorf("isJSON(%q) = %v, want %v", tc.contentType, got, tc.want)
			}
		})
	}
}
