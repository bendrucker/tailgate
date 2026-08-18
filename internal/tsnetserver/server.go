// Package tsnetserver runs tailgate's embedded Tailscale node and Funnel
// listener.
//
// A Server owns the node's lifecycle in the order the proxy seam requires:
// Up joins the tailnet and yields the FQDN every canonical resource URL is
// built from, ListenFunnel exposes the node on the public internet, and
// shutdown runs StopAccepting, then the caller's transport drain, then Close.
package tsnetserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// ErrClosed is returned by operations attempted after Close.
var ErrClosed = errors.New("tsnetserver: server closed")

// funnelPorts are the only TCP ports Tailscale Funnel supports.
var funnelPorts = map[int]bool{443: true, 8443: true, 10000: true}

// node is the part of tsnet.Server this package drives. Joining a tailnet
// needs a control server, so the interface exists to let tests exercise the
// lifecycle around tsnet without one.
type node interface {
	Up(ctx context.Context) (*ipnstate.Status, error)
	ListenFunnel(network, addr string, opts ...tsnet.FunnelOption) (net.Listener, error)
	HTTPClient() *http.Client
	Close() error
}

// Config describes the embedded node and its public listener.
type Config struct {
	// Hostname is the name the node presents to the control server, and the
	// first label of the tailnet FQDN.
	Hostname string
	// StateDir holds the node's persistent state, including its machine key.
	StateDir string
	// Port is the Funnel port: 443, 8443, or 10000.
	Port int
	// AuthKey authenticates the node on first join. When empty, tsnet falls
	// back to TS_AUTHKEY and then to an interactive login URL.
	AuthKey string
	// Logger, when set, receives tsnet's user-facing messages, which include
	// the interactive login URL printed on an unauthenticated first join.
	Logger *slog.Logger
	// OpenLoginURL hands that login URL to the platform's default URL handler
	// so an interactive first join does not require copying it out of the log.
	// It is off by default because tailgate's deployment target is launchd,
	// where no browser is watching and no one is there to complete the join.
	OpenLoginURL bool
}

// Server is tailgate's embedded Tailscale node.
type Server struct {
	node node
	addr string

	mu       sync.Mutex
	fqdn     string
	listener net.Listener
	stopped  bool
	closed   bool
}

// New configures a node from cfg without contacting the control server. The
// Funnel port is validated here because Funnel serves only 443, 8443, and
// 10000, and a listener on any other port would come up locally and then be
// unreachable from the internet.
func New(cfg Config) (*Server, error) {
	if cfg.Hostname == "" {
		return nil, fmt.Errorf("tsnetserver: hostname is required")
	}
	if !funnelPorts[cfg.Port] {
		return nil, fmt.Errorf("tsnetserver: port %d is not a Funnel port (443, 8443, 10000)", cfg.Port)
	}

	srv := &tsnet.Server{
		Hostname: cfg.Hostname,
		Dir:      cfg.StateDir,
		AuthKey:  cfg.AuthKey,
	}
	if cfg.Logger != nil {
		// TAILGATE_TSNET_DEBUG surfaces tsnet's internal tailscaled logs,
		// which otherwise go only to logtail. The funnel ingress wiring is
		// only observable there.
		if os.Getenv("TAILGATE_TSNET_DEBUG") != "" {
			srv.Logf = func(format string, args ...any) {
				cfg.Logger.Info("tsnet: " + fmt.Sprintf(format, args...))
			}
		}
		srv.UserLogf = func(format string, args ...any) {
			cfg.Logger.Info(fmt.Sprintf(format, args...))
		}
		if cfg.OpenLoginURL {
			srv.UserLogf = (&opener{open: openURL, logger: cfg.Logger}).userLogf(srv.UserLogf)
		}
	}
	return newServer(srv, cfg.Port), nil
}

func newServer(n node, port int) *Server {
	return &Server{node: n, addr: net.JoinHostPort("", strconv.Itoa(port))}
}

// Up joins the tailnet and reports the node's FQDN, blocking until the node is
// up or ctx expires. The name is unknowable before the join, so everything
// derived from it, including the canonical resource URLs, must be built after
// this call. The returned name may carry a trailing dot, which resource.NewURLs
// strips. Repeat calls return the joined name without re-contacting control.
func (s *Server) Up(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return "", ErrClosed
	}
	if s.fqdn != "" {
		fqdn := s.fqdn
		s.mu.Unlock()
		return fqdn, nil
	}
	s.mu.Unlock()

	status, err := s.node.Up(ctx)
	if err != nil {
		// tsnet's error does not report whether the deadline passed. Carrying
		// ctx.Err alongside it keeps errors.Is(err, context.DeadlineExceeded)
		// true for the caller.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("tsnetserver: node did not join the tailnet in time: %w", errors.Join(err, ctxErr))
		}
		return "", fmt.Errorf("tsnetserver: join tailnet: %w", err)
	}
	if status == nil || status.Self == nil || status.Self.DNSName == "" {
		return "", fmt.Errorf("tsnetserver: node joined without a tailnet DNS name")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Close can complete while the join is in flight, since the lock is
	// released across it so shutdown never waits on control.
	if s.closed {
		return "", ErrClosed
	}
	s.fqdn = status.Self.DNSName
	return s.fqdn, nil
}

// FQDN reports the tailnet DNS name learned by Up, or the empty string before
// the node has joined.
func (s *Server) FQDN() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fqdn
}

// ListenFunnel exposes the node on the public internet at the configured
// Funnel port. Tailscale terminates TLS, so the listener yields plain HTTP
// connections, and the tailnet policy must grant the node the funnel
// attribute. The listener also serves tailnet peers dialing the same port.
// Every request is authenticated by bearer token either way, since Funnel
// strips tailnet identity and the token is the only identity signal.
//
// The caller owns serving on the returned listener. StopAccepting closes it,
// which keeps shutdown sequenced.
func (s *Server) ListenFunnel() (net.Listener, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrClosed
	}
	if s.listener != nil {
		return nil, fmt.Errorf("tsnetserver: funnel listener already started on %s", s.addr)
	}
	ln, err := s.node.ListenFunnel("tcp", s.addr)
	if err != nil {
		return nil, fmt.Errorf("tsnetserver: listen funnel on %s: %w", s.addr, err)
	}
	s.listener = ln
	return ln, nil
}

// StopAccepting closes the Funnel listener, the first step of graceful
// shutdown: no new connection is accepted while the caller drains transports
// and the node stays up for in-flight work. It is a no-op before the listener
// starts and on repeat calls.
func (s *Server) StopAccepting() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopAccepting()
}

func (s *Server) stopAccepting() error {
	if s.listener == nil || s.stopped {
		return nil
	}
	s.stopped = true
	if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("tsnetserver: stop funnel listener: %w", err)
	}
	return nil
}

// Close leaves the tailnet, the last step of shutdown. It stops the listener
// first if the caller has not, so an abrupt Close still stops accepting before
// the node goes away. Close is idempotent.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	err := s.stopAccepting()
	if closeErr := s.node.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
		err = errors.Join(err, fmt.Errorf("tsnetserver: close node: %w", closeErr))
	}
	return err
}

// HTTPClient returns a client that dials over the tailnet. The auth verifier
// introspects tsidp through it: tsidp authenticates that path by tailnet node
// identity (WhoIs), so tailgate needs no stored client secret, and a client
// dialing the public internet would fail that check.
func (s *Server) HTTPClient() *http.Client {
	return s.node.HTTPClient()
}
