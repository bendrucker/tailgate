package auth

import (
	"container/list"
	"sync"
	"time"
)

// tokenCache maps a token digest to a value that expires. Entries are evicted
// least-recently-used once the cache holds max of them, which bounds the memory
// an unauthenticated client can cause tailgate to allocate by spraying distinct
// tokens at the Funnel endpoint. A max of zero or less disables the cache.
type tokenCache[T any] struct {
	mu    sync.Mutex
	max   int
	order *list.List
	items map[string]*list.Element
}

type cacheEntry[T any] struct {
	key     string
	value   T
	expires time.Time
}

func newTokenCache[T any](max int) *tokenCache[T] {
	return &tokenCache[T]{
		max:   max,
		order: list.New(),
		items: make(map[string]*list.Element),
	}
}

// get returns the value stored for key if it has not expired by now.
func (c *tokenCache[T]) get(key string, now time.Time) (T, bool) {
	var zero T
	if c.max <= 0 {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.items[key]
	if !ok {
		return zero, false
	}
	entry := el.Value.(*cacheEntry[T])
	if !now.Before(entry.expires) {
		c.remove(el)
		return zero, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

// put stores value under key until expires, dropping the least recently used
// entry when the cache is full. An expiry already reached at now is not stored,
// so a caller cannot install an entry that is served once and then expires.
func (c *tokenCache[T]) put(key string, value T, expires, now time.Time) {
	if c.max <= 0 || !now.Before(expires) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.items[key]; ok {
		entry := el.Value.(*cacheEntry[T])
		entry.value, entry.expires = value, expires
		c.order.MoveToFront(el)
		return
	}
	for c.order.Len() >= c.max {
		c.remove(c.order.Back())
	}
	c.items[key] = c.order.PushFront(&cacheEntry[T]{key: key, value: value, expires: expires})
}

func (c *tokenCache[T]) remove(el *list.Element) {
	if el == nil {
		return
	}
	c.order.Remove(el)
	delete(c.items, el.Value.(*cacheEntry[T]).key)
}

func (c *tokenCache[T]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
