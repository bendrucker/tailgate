// Package tsnetserver runs tailgate's embedded Tailscale node and Funnel listener.
package tsnetserver

import (
	"context"
	"fmt"
	"net"

	"tailscale.com/tsnet"
)

// New returns a tsnet server configured to join the tailnet as hostname, storing
// node state under dir.
func New(hostname, dir string) *tsnet.Server {
	return &tsnet.Server{
		Hostname: hostname,
		Dir:      dir,
	}
}

// FQDN brings the node up if needed and reports its tailnet DNS name. The name
// is unknowable before the node joins, so everything derived from it, like the
// canonical resource URLs, must be constructed after this call. The returned
// name may carry a trailing dot, which resource.NewURLs strips.
func FQDN(ctx context.Context, srv *tsnet.Server) (string, error) {
	status, err := srv.Up(ctx)
	if err != nil {
		return "", fmt.Errorf("tsnetserver: up: %w", err)
	}
	if status.Self == nil || status.Self.DNSName == "" {
		return "", fmt.Errorf("tsnetserver: node has no DNS name")
	}
	return status.Self.DNSName, nil
}

// ListenFunnel exposes srv on the public internet via Tailscale Funnel. Tailscale
// terminates TLS, so the returned listener yields plain HTTP connections. Funnel
// supports TCP ports 443, 8443, and 10000 only, and the node needs the funnel
// attribute in the tailnet policy.
func ListenFunnel(srv *tsnet.Server, addr string) (net.Listener, error) {
	return srv.ListenFunnel("tcp", addr)
}
