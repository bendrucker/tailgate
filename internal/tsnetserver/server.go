// Package tsnetserver runs tailgate's embedded Tailscale node and Funnel listener.
package tsnetserver

import (
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

// ListenFunnel exposes srv on the public internet via Tailscale Funnel. Tailscale
// terminates TLS, so the returned listener yields plain HTTP connections. Funnel
// supports TCP ports 443, 8443, and 10000 only, and the node needs the funnel
// attribute in the tailnet policy.
func ListenFunnel(srv *tsnet.Server, addr string) (net.Listener, error) {
	return srv.ListenFunnel("tcp", addr)
}
