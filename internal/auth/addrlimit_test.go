package auth

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return addr
}

func TestAddrLimiterSpendsBurstThenRefills(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	limiter := newAddrLimiter(16, 3, time.Second)
	addr := mustAddr(t, "203.0.113.7")

	for i := range 3 {
		if !limiter.allow(addr, start) {
			t.Fatalf("request %d within the burst was refused", i)
		}
	}
	if limiter.allow(addr, start) {
		t.Fatal("a request past the burst was allowed")
	}
	// A clock standing still refills nothing, and must not drain the bucket by
	// elapsing backwards either.
	if limiter.allow(addr, start.Add(-time.Minute)) {
		t.Fatal("a request at a clock that moved backwards was allowed")
	}
	if !limiter.allow(addr, start.Add(time.Second)) {
		t.Fatal("a request after one refill interval was refused")
	}
	if limiter.allow(addr, start.Add(time.Second)) {
		t.Fatal("a second request on one refilled token was allowed")
	}
	// Refill is capped at the burst rather than accruing over idle time.
	for i := range 3 {
		if !limiter.allow(addr, start.Add(time.Hour)) {
			t.Fatalf("request %d after a long idle period was refused", i)
		}
	}
	if limiter.allow(addr, start.Add(time.Hour)) {
		t.Fatal("the bucket accrued more than the burst while idle")
	}
}

func TestAddrLimiterKeysAddresses(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)

	for _, tc := range []struct {
		name    string
		spender string
		other   string
		shared  bool
	}{
		{
			name:    "ipv6 addresses in one site prefix",
			spender: "2001:db8:1::1",
			other:   "2001:db8:1:ffff::2",
			shared:  true,
		},
		{
			name:    "ipv6 addresses in different site prefixes",
			spender: "2001:db8:1::1",
			other:   "2001:db8:2::1",
			shared:  false,
		},
		{
			name:    "distinct ipv4 addresses",
			spender: "203.0.113.7",
			other:   "203.0.113.8",
			shared:  false,
		},
		{
			name:    "ipv4 address and its mapped ipv6 spelling",
			spender: "203.0.113.7",
			other:   "::ffff:203.0.113.7",
			shared:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limiter := newAddrLimiter(16, 1, time.Second)
			if !limiter.allow(mustAddr(t, tc.spender), start) {
				t.Fatalf("the first request from %s was refused", tc.spender)
			}
			if allowed := limiter.allow(mustAddr(t, tc.other), start); allowed == tc.shared {
				t.Errorf("%s allowed = %v after %s spent its token, want %v", tc.other, allowed, tc.spender, !tc.shared)
			}
		})
	}
}

// The zero Addr is what a request whose address could not be recovered is
// charged to. It must behave like any other key, so a plumbing gap costs those
// requests throughput rather than removing the limit for them.
func TestAddrLimiterChargesUnknownAddressesToOneBucket(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	limiter := newAddrLimiter(16, 2, time.Second)

	for i := range 2 {
		if !limiter.allow(netip.Addr{}, start) {
			t.Fatalf("request %d from an unknown address was refused", i)
		}
	}
	if limiter.allow(netip.Addr{}, start) {
		t.Fatal("an unknown address got a fresh bucket rather than sharing one")
	}
	if limiter.len() != 1 {
		t.Errorf("table holds %d entries, want the one shared bucket", limiter.len())
	}
}

func TestAddrLimiterTableStaysBounded(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	const max = 64
	limiter := newAddrLimiter(max, 1, time.Second)

	for i := range max * 10 {
		limiter.allow(mustAddr(t, fmt.Sprintf("198.51.100.%d", i%256)), start)
		limiter.allow(mustAddr(t, fmt.Sprintf("2001:db8:%x::1", i)), start)
		if got := limiter.len(); got > max {
			t.Fatalf("table holds %d entries after %d addresses, want at most %d", got, i, max)
		}
	}
}
