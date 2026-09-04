package authserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// table holds short-lived, single-use state keyed by a random handle: a
// pending consent, an authorization code, or a redeemed code's tokens. Each
// entry is taken at most once, and the table is bounded so a caller who
// never completes cannot grow it without limit.
type table[T any] struct {
	max int
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[string]tableEntry[T]
}

type tableEntry[T any] struct {
	value   T
	expires time.Time
}

func newTable[T any](max int, ttl time.Duration, now func() time.Time) *table[T] {
	return &table[T]{max: max, ttl: ttl, now: now, entries: make(map[string]tableEntry[T])}
}

// put reports false when the table is full of live entries, which the caller
// answers as a temporary refusal.
func (t *table[T]) put(value T) (string, bool) {
	handle := newHandle()
	if !t.set(handle, value) {
		return "", false
	}
	return handle, true
}

// set stores value under a handle the caller already holds, which is how a
// redeemed code is remembered under the code itself.
func (t *table[T]) set(handle string, value T) bool {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.entries) >= t.max {
		t.sweep(now)
	}
	if len(t.entries) >= t.max {
		return false
	}
	t.entries[digest(handle)] = tableEntry[T]{value: value, expires: now.Add(t.ttl)}
	return true
}

// take returns and forgets the value under handle, if it is live.
func (t *table[T]) take(handle string) (T, bool) {
	var zero T
	key := digest(handle)
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if !ok {
		return zero, false
	}
	delete(t.entries, key)
	if !now.Before(entry.expires) {
		return zero, false
	}
	return entry.value, true
}

// sweep runs under t.mu.
func (t *table[T]) sweep(now time.Time) {
	for key, entry := range t.entries {
		if !now.Before(entry.expires) {
			delete(t.entries, key)
		}
	}
}

func (t *table[T]) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// newHandle mints an unguessable handle: 32 random bytes, base64url.
func newHandle() string {
	raw := make([]byte, 32)
	rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// digest keys the table by a hash of the handle, so a heap dump yields no
// live code or consent handle.
func digest(handle string) string {
	sum := sha256.Sum256([]byte(handle))
	return string(sum[:])
}
