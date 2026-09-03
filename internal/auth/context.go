package auth

import (
	"context"
	"net/netip"
)

type identityKey struct{}

type clientAddrKey struct{}

type peerAddrKey struct{}

// WithIdentity returns a context carrying the authorized caller. The router
// sets it after verification and authorization succeed, so downstream code can
// treat its presence as proof the request was authorized.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// IdentityFrom returns the authorized caller, or false if the context carries
// none. Transports use it to scope per-identity session caps and audit fields.
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(identityKey{}).(Identity)
	return id, ok
}

// WithClientAddr returns a context carrying the address the request arrived
// from, for logs and any per-client accounting. Funnel replaces RemoteAddr
// with the relaying node, so the address must be recovered from the
// connection and put here before the handler runs.
func WithClientAddr(ctx context.Context, addr netip.Addr) context.Context {
	return context.WithValue(ctx, clientAddrKey{}, addr)
}

// ClientAddrFrom returns the address the request arrived from, or the zero
// Addr when the context carries none. There is deliberately no second result:
// an address that could not be recovered must still be charged, and a bool
// invites a caller to read "missing" as "exempt". The zero Addr is a valid map
// key that no real address collides with, so every such request shares one
// bucket and a plumbing gap costs throughput rather than the limit.
func ClientAddrFrom(ctx context.Context) netip.Addr {
	addr, _ := ctx.Value(clientAddrKey{}).(netip.Addr)
	return addr
}

// WithPeerAddr returns a context carrying the tailnet address the connection
// came from, which the authorization server resolves to a person with WhoIs.
// The router sets it only on a connection that is not Funnel ingress: a
// Funnel connection's RemoteAddr is the Tailscale relay, itself a tailnet
// peer, and WhoIs on it would name the relay as the person.
func WithPeerAddr(ctx context.Context, addr netip.AddrPort) context.Context {
	return context.WithValue(ctx, peerAddrKey{}, addr)
}

// PeerAddrFrom returns the tailnet peer address, or the zero AddrPort when
// the request arrived over Funnel or the context carries none. A zero value
// means the person cannot be identified, never that identification may be
// skipped.
func PeerAddrFrom(ctx context.Context) netip.AddrPort {
	addr, _ := ctx.Value(peerAddrKey{}).(netip.AddrPort)
	return addr
}
