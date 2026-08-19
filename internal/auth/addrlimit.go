package auth

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// ipv6PrefixBits is the granularity an IPv6 client is limited at. RFC 6177
// assigns an end site a /48, and every address inside one is the holder's to
// rotate through, so a limit keyed by full address limits nobody. A /64 is the
// smaller unit but one customer routinely holds many of them.
const ipv6PrefixBits = 48

// addrLimiter rate-limits by client address, bounding the introspection round
// trips one source can cause. The global concurrency gate bounds what tsidp
// absorbs in aggregate. This bounds any one source's claim on that budget, so a
// spray from a single address cannot hold every slot while verified callers
// shed.
//
// The rate is a token bucket rather than an in-flight cap because in-flight is
// already bounded and says nothing about a slow spray, which is the shape a
// source with one address and time takes.
type addrLimiter struct {
	mu       sync.Mutex
	max      int
	burst    float64
	interval time.Duration
	order    *list.List
	items    map[netip.Addr]*list.Element
}

type addrBucket struct {
	key    netip.Addr
	tokens float64
	last   time.Time
}

func newAddrLimiter(max int, burst float64, interval time.Duration) *addrLimiter {
	return &addrLimiter{
		max:      max,
		burst:    burst,
		interval: interval,
		order:    list.New(),
		items:    make(map[netip.Addr]*list.Element),
	}
}

// allow charges one token to addr's bucket and reports whether it was there to
// spend. A limiter with no bound configured allows everything.
//
// The table is bounded by pure LRU with no expiry, so the eviction that makes
// room hands the evicted key a full bucket the next time it appears. That
// amnesty costs nothing: a source able to force eviction is a source able to
// present addresses that have no bucket at all.
func (l *addrLimiter) allow(addr netip.Addr, now time.Time) bool {
	if l == nil || l.max <= 0 || l.burst <= 0 || l.interval <= 0 {
		return true
	}
	key := limiterKey(addr)

	l.mu.Lock()
	defer l.mu.Unlock()

	el, ok := l.items[key]
	if !ok {
		for l.order.Len() >= l.max {
			l.remove(l.order.Back())
		}
		el = l.order.PushFront(&addrBucket{key: key, tokens: l.burst, last: now})
		l.items[key] = el
	} else {
		l.order.MoveToFront(el)
	}

	bucket := el.Value.(*addrBucket)
	// A clock that has not advanced refills nothing. Elapsed time running
	// backwards would otherwise drain the bucket rather than leave it alone.
	if elapsed := now.Sub(bucket.last); elapsed > 0 {
		bucket.tokens = min(l.burst, bucket.tokens+float64(elapsed)/float64(l.interval))
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func (l *addrLimiter) remove(el *list.Element) {
	if el == nil {
		return
	}
	l.order.Remove(el)
	delete(l.items, el.Value.(*addrBucket).key)
}

func (l *addrLimiter) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// limiterKey reduces an address to the unit that is charged: an IPv4 address
// stands alone, and an IPv6 address is charged to its site prefix. An
// IPv4-mapped address is unmapped first so one client cannot hold two buckets
// by presenting both spellings.
func limiterKey(addr netip.Addr) netip.Addr {
	addr = addr.Unmap()
	if !addr.Is6() {
		return addr
	}
	prefix, err := addr.Prefix(ipv6PrefixBits)
	if err != nil {
		return addr
	}
	return prefix.Addr()
}
