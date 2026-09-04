package cimd

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrForbiddenAddress is returned by the egress guard when a client ID
// resolves to an address the fetcher will not dial.
var ErrForbiddenAddress = errors.New("cimd: address is not reachable for client metadata")

// dialTimeout bounds one connection attempt, so a client ID resolving to a
// black hole cannot hold an authorization request open.
const dialTimeout = 5 * time.Second

// forbiddenPrefixes are the ranges the standard library's address predicates
// do not cover: the carrier-grade NAT block Tailscale assigns node addresses
// from, its IPv6 ULA prefix, and the RFC 1122 "this network" block, which
// Linux routes to the local host for any address in it and not only 0.0.0.0.
// Every tailnet peer, including tailgate's own node and any private service
// reachable through it, lives in one of the first two.
var forbiddenPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	netip.MustParsePrefix("0.0.0.0/8"),
}

// NewClient builds the client that fetches documents in production. Its
// transport dials only global unicast addresses, follows no redirects, sends
// nothing through a proxy, and bounds the whole exchange.
//
// The guard runs on the address a name resolved to, after DNS, so a name that
// resolves to a private address is refused at the same point as a literal one.
// Refusing redirects closes the other route to an internal target, and keeps
// the document at the URL the client_id names, which is what the draft binds
// it to.
func NewClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: dialTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrForbiddenAddress, err)
			}
			if !allowedAddr(ap.Addr()) {
				return fmt.Errorf("%w: %s", ErrForbiddenAddress, ap.Addr())
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: dialTimeout,
		MaxIdleConns:          8,
		IdleConnTimeout:       time.Minute,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// allowedAddr reports whether the fetcher may dial addr. IPv4-mapped IPv6
// addresses are unmapped first so the IPv4 rules apply to them.
func allowedAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	switch {
	case !addr.IsValid(),
		!addr.IsGlobalUnicast(),
		addr.IsPrivate(),
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsUnspecified(),
		addr.IsMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsLinkLocalMulticast():
		return false
	}
	for _, prefix := range forbiddenPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
