package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingIssuer serves OIDC discovery plus an introspection endpoint the test
// controls, counting the round trips each Verify actually costs. The count is
// the abuse-control assertion: a token sprayed at Funnel must not translate
// into unbounded work at tsidp.
type countingIssuer struct {
	*httptest.Server
	hits atomic.Int64
}

func newCountingIssuer(t *testing.T, introspect http.HandlerFunc) *countingIssuer {
	t.Helper()
	issuer := &countingIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"introspection_endpoint":%q}`, base, base+"/introspect")
	})
	mux.HandleFunc("POST /introspect", func(w http.ResponseWriter, r *http.Request) {
		issuer.hits.Add(1)
		introspect(w, r)
	})
	issuer.Server = httptest.NewServer(mux)
	t.Cleanup(issuer.Close)
	return issuer
}

type testClock struct {
	mu sync.Mutex
	at time.Time
}

func newTestClock() *testClock {
	return &testClock{at: time.Unix(1_800_000_000, 0)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

func newTestVerifier(t *testing.T, issuer *countingIssuer, clock *testClock, opts ...VerifierOption) *Verifier {
	t.Helper()
	opts = append([]VerifierOption{WithClock(clock.now)}, opts...)
	verifier, err := NewVerifier(t.Context(), issuer.Client(), issuer.URL, opts...)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return verifier
}

func activeClaims(clock *testClock, lifetime time.Duration) map[string]any {
	return map[string]any{
		"active":   true,
		"exp":      float64(clock.now().Add(lifetime).Unix()),
		"sub":      "12345",
		"username": "bendrucker@github",
		"email":    "bvdrucker@gmail.com",
		"aud":      []any{"client-id", testResource},
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode introspection response: %v", err)
	}
}

func TestVerifyRejectsMalformedBearersWithoutIntrospecting(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "crlf header injection", token: "deadbeef\r\nX-Injected: 1"},
		{name: "bare line feed", token: "dead\nbeef"},
		{name: "embedded space", token: "dead beef"},
		{name: "null byte", token: "dead\x00beef"},
		{name: "tab", token: "dead\tbeef"},
		{name: "non ascii", token: "töken-ünicode"},
		{name: "quote and backslash", token: `dead"beef\`},
		{name: "percent escaped crlf", token: "deadbeef%0d%0a"},
		{name: "form field smuggling", token: "deadbeef&token_type_hint=refresh_token"},
		{name: "oversized", token: strings.Repeat("a", maxTokenLength+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
				t.Error("malformed bearer reached the issuer")
				writeJSON(t, w, map[string]any{"active": false})
			})
			verifier := newTestVerifier(t, issuer, newTestClock())

			_, err := verifier.Verify(t.Context(), tc.token, testResource)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got %v", err)
			}
			if tc.token != "" && strings.Contains(err.Error(), tc.token) {
				t.Errorf("error text repeats the bearer: %v", err)
			}
			if hits := issuer.hits.Load(); hits != 0 {
				t.Errorf("expected 0 introspection round trips, got %d", hits)
			}
		})
	}
}

func TestVerifyDeniesWellFormedGarbage(t *testing.T) {
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"active": false})
	})
	verifier := newTestVerifier(t, issuer, newTestClock())

	_, err := verifier.Verify(t.Context(), "not-a-real-token", testResource)
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if hits := issuer.hits.Load(); hits != 1 {
		t.Errorf("expected 1 introspection round trip, got %d", hits)
	}
}

func TestVerifyFailsClosedWhenIntrospectionMisbehaves(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "bad gateway",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
			},
		},
		{
			name: "bad request",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name: "introspection caller unauthorized",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
		},
		{
			name: "truncated json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"active":true,"sub":`)
			},
		},
		{
			name: "json array not object",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `[{"active":true}]`)
			},
		},
		{
			name: "empty body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
			},
		},
		{
			name: "html error page",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprint(w, `<html><body>authenticate here</body></html>`)
			},
		},
		{
			name: "plain text content type",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				fmt.Fprint(w, `{"active":true,"exp":9999999999,"sub":"12345","aud":"`+testResource+`"}`)
			},
		},
		{
			name: "missing content type",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header()["Content-Type"] = nil
				fmt.Fprint(w, `{"active":true,"exp":9999999999,"sub":"12345","aud":"`+testResource+`"}`)
			},
		},
		{
			name: "body past the read limit",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"active":true,"pad":"`+strings.Repeat("a", 2<<20)+`"}`)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newCountingIssuer(t, tc.handler)
			verifier := newTestVerifier(t, issuer, newTestClock())

			_, err := verifier.Verify(t.Context(), "deadbeef", testResource)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("expected ErrUnavailable, got %v", err)
			}
			if errors.Is(err, ErrInvalidToken) {
				t.Fatalf("an issuer failure must not classify the token as invalid: %v", err)
			}
		})
	}
}

func TestVerifyFailsClosedWhenIntrospectionStalls(t *testing.T) {
	release := make(chan struct{})
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
	})
	// Registered after the server so it runs first: httptest.Server.Close waits
	// for outstanding requests, and these are parked in the handler.
	t.Cleanup(sync.OnceFunc(func() { close(release) }))

	t.Run("introspection timeout", func(t *testing.T) {
		verifier := newTestVerifier(t, issuer, newTestClock(), WithIntrospectionTimeout(20*time.Millisecond))
		_, err := verifier.Verify(t.Context(), "deadbeef", testResource)
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrUnavailable, got %v", err)
		}
	})

	t.Run("caller gives up", func(t *testing.T) {
		verifier := newTestVerifier(t, issuer, newTestClock())
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		_, err := verifier.Verify(ctx, "deadbeef", testResource)
		if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrUnavailable, got %v", err)
		}
	})
}

func TestVerifyCachesInactiveVerdictBriefly(t *testing.T) {
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"active": false})
	})
	clock := newTestClock()
	verifier := newTestVerifier(t, issuer, clock, WithNegativeCacheTTL(time.Minute))

	for range 5 {
		if _, err := verifier.Verify(t.Context(), "sprayed", testResource); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	}
	if hits := issuer.hits.Load(); hits != 1 {
		t.Errorf("expected repeats of a rejected token to be free, got %d round trips", hits)
	}

	if _, err := verifier.Verify(t.Context(), "sprayed-differently", testResource); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if hits := issuer.hits.Load(); hits != 2 {
		t.Errorf("expected a distinct token to cost a round trip, got %d total", hits)
	}

	clock.advance(time.Minute)
	if _, err := verifier.Verify(t.Context(), "sprayed", testResource); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
	if hits := issuer.hits.Load(); hits != 3 {
		t.Errorf("expected the rejection to lapse after its TTL, got %d total round trips", hits)
	}
}

func TestVerifyKeepsIssuerFailuresRetryable(t *testing.T) {
	clock := newTestClock()
	var healthy atomic.Bool
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(t, w, activeClaims(clock, 5*time.Minute))
	})
	verifier := newTestVerifier(t, issuer, clock)

	for range 2 {
		if _, err := verifier.Verify(t.Context(), "deadbeef", testResource); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected ErrUnavailable, got %v", err)
		}
	}
	if hits := issuer.hits.Load(); hits != 2 {
		t.Errorf("expected a failed introspection to stay retryable, got %d round trips", hits)
	}

	healthy.Store(true)
	if _, err := verifier.Verify(t.Context(), "deadbeef", testResource); err != nil {
		t.Fatalf("expected the token to verify once the issuer recovered: %v", err)
	}
}

func TestVerifyCachesUntilTokenExpiry(t *testing.T) {
	for _, tc := range []struct {
		name        string
		lifetime    time.Duration
		ceiling     time.Duration
		size        int
		advance     time.Duration
		wantHits    int64
		wantInvalid bool
	}{
		{
			name:     "reuses claims within the token lifetime",
			lifetime: 5 * time.Minute,
			ceiling:  5 * time.Minute,
			size:     16,
			advance:  4 * time.Minute,
			wantHits: 1,
		},
		{
			name:        "never serves a token past its exp",
			lifetime:    time.Minute,
			ceiling:     5 * time.Minute,
			size:        16,
			advance:     90 * time.Second,
			wantHits:    2,
			wantInvalid: true,
		},
		{
			name:     "ceiling bounds a long lived token",
			lifetime: time.Hour,
			ceiling:  5 * time.Minute,
			size:     16,
			advance:  6 * time.Minute,
			wantHits: 2,
		},
		{
			name:     "disabled cache introspects every request",
			lifetime: 5 * time.Minute,
			ceiling:  5 * time.Minute,
			size:     0,
			wantHits: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newTestClock()
			issued := clock.now()
			issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
				writeJSON(t, w, map[string]any{
					"active": true,
					"exp":    float64(issued.Add(tc.lifetime).Unix()),
					"sub":    "12345",
					"aud":    []any{"client-id", testResource},
				})
			})
			verifier := newTestVerifier(t, issuer, clock, WithCacheTTL(tc.ceiling), WithCacheSize(tc.size))

			if _, err := verifier.Verify(t.Context(), "deadbeef", testResource); err != nil {
				t.Fatalf("Verify: %v", err)
			}
			clock.advance(tc.advance)

			_, err := verifier.Verify(t.Context(), "deadbeef", testResource)
			if tc.wantInvalid {
				if !errors.Is(err, ErrInvalidToken) {
					t.Fatalf("expected ErrInvalidToken past exp, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if hits := issuer.hits.Load(); hits != tc.wantHits {
				t.Errorf("expected %d introspection round trips, got %d", tc.wantHits, hits)
			}
		})
	}
}

func TestVerifyRechecksAudienceOnCacheHit(t *testing.T) {
	clock := newTestClock()
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, activeClaims(clock, 5*time.Minute))
	})
	verifier := newTestVerifier(t, issuer, clock)

	if _, err := verifier.Verify(t.Context(), "deadbeef", testResource); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	other := "https://tailgate.tail1234.ts.net/mcp/linear"
	if _, err := verifier.Verify(t.Context(), "deadbeef", other); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a cached token must not verify for an upstream outside its audience, got %v", err)
	}
	if hits := issuer.hits.Load(); hits != 1 {
		t.Errorf("expected one round trip to serve both upstreams, got %d", hits)
	}
}

func TestVerifyDoesNotCacheClaimsWithoutExp(t *testing.T) {
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"active": true,
			"sub":    "12345",
			"aud":    testResource,
		})
	})
	verifier := newTestVerifier(t, issuer, newTestClock())

	for range 2 {
		if _, err := verifier.Verify(t.Context(), "deadbeef", testResource); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("expected ErrInvalidToken, got %v", err)
		}
	}
	if hits := issuer.hits.Load(); hits != 2 {
		t.Errorf("claims with no expiry must not be cached, got %d round trips", hits)
	}
}

func TestVerifyCachesAreBounded(t *testing.T) {
	t.Run("rejected tokens", func(t *testing.T) {
		issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, map[string]any{"active": false})
		})
		verifier := newTestVerifier(t, issuer, newTestClock(), WithNegativeCacheSize(8))

		for i := range 200 {
			if _, err := verifier.Verify(t.Context(), fmt.Sprintf("sprayed-%d", i), testResource); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("expected ErrInvalidToken, got %v", err)
			}
		}
		if size := verifier.inactive.len(); size != 8 {
			t.Errorf("expected the negative cache to hold its bound of 8 entries, got %d", size)
		}
	})

	t.Run("verified tokens", func(t *testing.T) {
		clock := newTestClock()
		issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, activeClaims(clock, 5*time.Minute))
		})
		verifier := newTestVerifier(t, issuer, clock, WithCacheSize(4))

		for i := range 50 {
			if _, err := verifier.Verify(t.Context(), fmt.Sprintf("token-%d", i), testResource); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		}
		if size := verifier.active.len(); size != 4 {
			t.Errorf("expected the verified-token cache to hold its bound of 4 entries, got %d", size)
		}
	})
}

func TestVerifyCollapsesConcurrentIntrospection(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)

	clock := newTestClock()
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		writeJSON(t, w, activeClaims(clock, 5*time.Minute))
	})
	closeRelease := sync.OnceFunc(func() { close(release) })
	t.Cleanup(closeRelease)
	// Caching is off so the round-trip count measures deduplication alone.
	verifier := newTestVerifier(t, issuer, clock, WithCacheSize(0), WithNegativeCacheSize(0))

	const callers = 32
	results := make([]error, callers)
	var launched, finished sync.WaitGroup
	launched.Add(callers)
	finished.Add(callers)
	for i := range callers {
		go func() {
			defer finished.Done()
			launched.Done()
			_, results[i] = verifier.Verify(context.Background(), "deadbeef", testResource)
		}()
	}

	launched.Wait()
	<-arrived
	// The first caller is parked in the handler; give the rest time to join it.
	time.Sleep(50 * time.Millisecond)
	closeRelease()
	finished.Wait()

	for i, err := range results {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if hits := issuer.hits.Load(); hits != 1 {
		t.Errorf("expected %d concurrent callers to cost 1 round trip, got %d", callers, hits)
	}
}

func TestVerifyShedsLoadPastConcurrencyLimit(t *testing.T) {
	const limit = 2
	release := make(chan struct{})
	arrivals := make(chan struct{}, limit)

	clock := newTestClock()
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, r *http.Request) {
		arrivals <- struct{}{}
		<-release
		writeJSON(t, w, activeClaims(clock, 5*time.Minute))
	})
	closeRelease := sync.OnceFunc(func() { close(release) })
	t.Cleanup(closeRelease)
	verifier := newTestVerifier(t, issuer, clock,
		WithIntrospectionConcurrency(limit),
		WithCacheSize(0),
		WithNegativeCacheSize(0),
	)

	holders := make([]error, limit)
	var occupying sync.WaitGroup
	for i := range limit {
		occupying.Add(1)
		go func() {
			defer occupying.Done()
			_, holders[i] = verifier.Verify(context.Background(), fmt.Sprintf("holder-%d", i), testResource)
		}()
	}
	for range limit {
		<-arrivals
	}

	_, err := verifier.Verify(t.Context(), "shed-me", testResource)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable once the introspection gate is full, got %v", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Fatalf("load shed must not classify the token as invalid: %v", err)
	}
	if hits := issuer.hits.Load(); hits != limit {
		t.Errorf("expected the shed request not to reach the issuer, got %d round trips", hits)
	}

	closeRelease()
	occupying.Wait()
	for i, err := range holders {
		if err != nil {
			t.Fatalf("holder %d: %v", i, err)
		}
	}

	if _, err := verifier.Verify(t.Context(), "shed-me", testResource); err != nil {
		t.Fatalf("expected the gate to reopen once calls finished: %v", err)
	}
}
