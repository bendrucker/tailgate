package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestTokenCacheRetention(t *testing.T) {
	stored := time.Unix(1_800_000_000, 0)
	for _, tc := range []struct {
		name     string
		max      int
		lifetime time.Duration
		read     time.Duration
		want     bool
	}{
		{
			name:     "serves an entry before it expires",
			max:      4,
			lifetime: time.Minute,
			read:     30 * time.Second,
			want:     true,
		},
		{
			name:     "drops an entry at its expiry",
			max:      4,
			lifetime: time.Minute,
			read:     time.Minute,
		},
		{
			name:     "drops an entry past its expiry",
			max:      4,
			lifetime: time.Minute,
			read:     2 * time.Minute,
		},
		{
			name:     "stores nothing when disabled",
			max:      0,
			lifetime: time.Minute,
		},
		{
			name:     "stores nothing that expires on arrival",
			max:      4,
			lifetime: 0,
		},
		{
			name:     "stores nothing already expired",
			max:      4,
			lifetime: -time.Minute,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newTokenCache[string](tc.max)
			cache.put("key", "value", stored.Add(tc.lifetime), stored)

			value, ok := cache.get("key", stored.Add(tc.read))
			if ok != tc.want {
				t.Fatalf("expected hit=%v, got %v", tc.want, ok)
			}
			if ok && value != "value" {
				t.Errorf("expected value %q, got %q", "value", value)
			}
			if !tc.want && cache.len() != 0 {
				t.Errorf("expected a missed entry to be dropped, cache holds %d", cache.len())
			}
		})
	}
}

func TestTokenCacheEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	expires := now.Add(time.Hour)
	cache := newTokenCache[string](3)
	for _, key := range []string{"a", "b", "c"} {
		cache.put(key, key, expires, now)
	}
	if _, ok := cache.get("a", now); !ok {
		t.Fatal("expected a to be cached")
	}
	cache.put("d", "d", expires, now)

	for key, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true} {
		if _, ok := cache.get(key, now); ok != want {
			t.Errorf("expected %q cached=%v, got %v", key, want, ok)
		}
	}
	if cache.len() != 3 {
		t.Errorf("expected the cache to hold its bound of 3, got %d", cache.len())
	}
}

func TestTokenCacheStaysBounded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := newTokenCache[string](8)
	for i := range 1000 {
		key := fmt.Sprintf("key-%d", i)
		cache.put(key, key, now.Add(time.Hour), now)
	}
	if cache.len() != 8 {
		t.Errorf("expected the cache to hold its bound of 8, got %d", cache.len())
	}
}

func TestTokenCacheRefreshesAnExistingKey(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cache := newTokenCache[string](2)
	cache.put("key", "old", now.Add(time.Minute), now)
	cache.put("key", "new", now.Add(time.Hour), now)

	if cache.len() != 1 {
		t.Fatalf("expected one entry, got %d", cache.len())
	}
	value, ok := cache.get("key", now.Add(30*time.Minute))
	if !ok {
		t.Fatal("expected the refreshed entry to outlive the original expiry")
	}
	if value != "new" {
		t.Errorf("expected value %q, got %q", "new", value)
	}
}

// The cache holds the decoded claim set for the token's remaining life and
// hands it to every caller, so a caller that reaches into a nested container
// would rewrite what the next request sees.
func TestVerifiedClaimsAreIsolatedFromTheCache(t *testing.T) {
	clock := newTestClock()
	issuer := newCountingIssuer(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, activeClaims(clock, time.Minute))
	})
	verifier := newTestVerifier(t, issuer, clock)

	first, err := verifier.Verify(t.Context(), "deadbeef", testResource)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	first.Claims["aud"].([]any)[0] = "tampered"
	first.Claims["sub"] = "tampered"

	second, err := verifier.Verify(t.Context(), "deadbeef", testResource)
	if err != nil {
		t.Fatalf("second Verify: %v", err)
	}
	if got := second.Claims["aud"].([]any)[0]; got != "client-id" {
		t.Errorf("aud[0] = %q, want %q: one caller's write reached another's claims", got, "client-id")
	}
	if got := second.Claims["sub"]; got != "12345" {
		t.Errorf("sub = %v, want %q", got, "12345")
	}
	if second.Subject != "12345" {
		t.Errorf("Subject = %q, want %q", second.Subject, "12345")
	}
}
