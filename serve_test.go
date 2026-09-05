package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/client/tailscale/apitype"

	"github.com/bendrucker/tailgate/internal/config"
)

// recorder captures the order of the shutdown steps, which is the whole
// contract: accepting must stop before anything drains, or a connection
// arriving mid-drain reaches a transport that is already refusing work.
type recorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *recorder) record(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

// fakeNode stands in for the embedded Tailscale node. Joining a tailnet needs
// a control server, so everything sequenced around the node is driven through
// this instead of one.
type fakeNode struct {
	steps *recorder

	fqdn  string
	upErr error
	// block holds the join open until its context expires, which is what a
	// node that cannot authenticate itself does.
	block bool

	listenErr error
	stopErr   error
	closeErr  error

	// listening closes once the Funnel listener is up, so a test knows serve
	// reached the point where it serves.
	listening chan struct{}

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func (n *fakeNode) Up(ctx context.Context) (string, error) {
	n.steps.record("up")
	if !n.block {
		return n.fqdn, n.upErr
	}
	<-ctx.Done()
	// tsnetserver.Server.Up joins the context error onto tsnet's own, which is
	// what keeps the deadline distinguishable from any other join failure.
	return "", fmt.Errorf("tsnetserver: node did not join the tailnet in time: %w",
		errors.Join(errors.New("tsnet: operation not permitted"), ctx.Err()))
}

// ListenFunnel hands back a loopback listener, so the HTTP server serving on
// it behaves as it does over Funnel.
func (n *fakeNode) ListenFunnel() (net.Listener, error) {
	n.steps.record("listen")
	if n.listenErr != nil {
		return nil, n.listenErr
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.listener = listener
	n.mu.Unlock()
	if n.listening != nil {
		close(n.listening)
	}
	return listener, nil
}

func (n *fakeNode) WhoIs(context.Context, netip.AddrPort) (*apitype.WhoIsResponse, error) {
	return nil, errors.New("no tailnet in this test")
}

func (n *fakeNode) StopAccepting() error {
	n.steps.record("stop")
	n.mu.Lock()
	listener := n.listener
	n.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
	return n.stopErr
}

// Close records once, since the real node's Close is idempotent and serve
// defers one behind the drain that already ran it.
func (n *fakeNode) Close() error {
	n.mu.Lock()
	closed := n.closed
	n.closed = true
	n.mu.Unlock()
	if closed {
		return nil
	}
	n.steps.record("close node")
	return n.closeErr
}

// fakeConnections stands in for the HTTP server. A real one that never served
// returns from Shutdown before it has done anything, which leaves the end of
// the chain unobservable.
type fakeConnections struct {
	steps       *recorder
	shutdownErr error
	closeErr    error
}

func (c *fakeConnections) Shutdown(context.Context) error {
	c.steps.record("connections shutdown")
	return c.shutdownErr
}

func (c *fakeConnections) Close() error {
	c.steps.record("connections close")
	return c.closeErr
}

// waitFor polls until done reports true, for the steps a goroutine takes on
// its own clock.
func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDrain(t *testing.T) {
	stopErr := errors.New("listener already closed")
	drainErr := errors.New("upstream still busy")
	shutdownErr := errors.New("connections still open")
	closeErr := errors.New("node already gone")

	for _, tc := range []struct {
		name        string
		stopErr     error
		drainErr    error
		shutdownErr error
		closeErr    error
		steps       []string
		expected    []error
	}{
		{
			name:  "clean",
			steps: []string{"stop", "router shutdown", "connections shutdown", "close node"},
		},
		{
			name:     "listener stop fails",
			stopErr:  stopErr,
			steps:    []string{"stop", "router shutdown", "connections shutdown", "close node"},
			expected: []error{stopErr},
		},
		{
			name:     "upstreams do not drain",
			drainErr: drainErr,
			steps:    []string{"stop", "router shutdown", "connections shutdown", "close node"},
			expected: []error{drainErr},
		},
		{
			// Whatever the deadline left is severed, so shutdown terminates
			// rather than waiting on a connection nobody is going to close.
			name:        "connections do not close",
			shutdownErr: shutdownErr,
			steps:       []string{"stop", "router shutdown", "connections shutdown", "connections close", "close node"},
		},
		{
			name:     "the node does not leave the tailnet",
			closeErr: closeErr,
			steps:    []string{"stop", "router shutdown", "connections shutdown", "close node"},
			expected: []error{closeErr},
		},
		{
			name:        "every step fails",
			stopErr:     stopErr,
			drainErr:    drainErr,
			shutdownErr: shutdownErr,
			closeErr:    closeErr,
			steps:       []string{"stop", "router shutdown", "connections shutdown", "connections close", "close node"},
			expected:    []error{stopErr, drainErr, closeErr},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			steps := &recorder{}
			err := drain(
				discardLogger(),
				&fakeNode{steps: steps, stopErr: tc.stopErr, closeErr: tc.closeErr},
				&fakeConnections{steps: steps, shutdownErr: tc.shutdownErr},
				&fakeServed{name: "router", steps: steps, shutdownErr: tc.drainErr},
			)

			if diff := cmp.Diff(tc.steps, steps.recorded()); diff != "" {
				t.Errorf("shutdown steps differ:\n%s", diff)
			}
			for _, expected := range tc.expected {
				if !errors.Is(err, expected) {
					t.Errorf("expected %v in %v", expected, err)
				}
			}
			if len(tc.expected) == 0 && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// TestServe drives the whole sequence against a node that never contacts a
// control server. Nothing may listen before the join has reported a name the
// config accepts, since every canonical resource URI is built from it.
func TestServe(t *testing.T) {
	joinErr := errors.New("funnel attribute missing")
	listenErr := errors.New("funnel attribute missing")

	for _, tc := range []struct {
		name string
		node *fakeNode
		// tailnet pins the name the node must join under.
		tailnet string
		wantErr bool
		steps   []string
	}{
		{
			name:  "serves until the context is canceled",
			node:  &fakeNode{fqdn: testFQDN},
			steps: []string{"up", "listen", "stop", "close node"},
		},
		{
			name:    "a join that fails never listens",
			node:    &fakeNode{upErr: joinErr},
			wantErr: true,
			steps:   []string{"up", "close node"},
		},
		{
			name:    "a name the config did not expect never listens",
			node:    &fakeNode{fqdn: testFQDN},
			tailnet: "other.ts.net",
			wantErr: true,
			steps:   []string{"up", "close node"},
		},
		{
			name:    "a listener that cannot start stops the process",
			node:    &fakeNode{fqdn: testFQDN, listenErr: listenErr},
			wantErr: true,
			steps:   []string{"up", "listen", "close node"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tailgate.hujson")
			writeConfig(t, path, "tailgate", "http://127.0.0.1:9000/mcp", "1")
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			cfg.Node.Tailnet = tc.tailnet

			steps := &recorder{}
			tc.node.steps = steps
			tc.node.listening = make(chan struct{})

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			served := make(chan error, 1)
			go func() { served <- serve(ctx, discardLogger(), tc.node, cfg, options{ConfigPath: path}) }()

			if tc.wantErr {
				if err := <-served; err == nil {
					t.Fatal("serve returned no error")
				}
			} else {
				select {
				case <-tc.node.listening:
				case err := <-served:
					t.Fatalf("serve returned before it listened: %v", err)
				}
				cancel()
				if err := <-served; err != nil {
					t.Fatalf("serve: %v", err)
				}
			}

			if diff := cmp.Diff(tc.steps, steps.recorded()); diff != "" {
				t.Errorf("node steps differ:\n%s", diff)
			}
		})
	}
}

// TestReloadOnSignal covers the wiring behind SIGHUP: a signal rebuilds the
// router, and the loop ends with the context rather than outliving the process
// it reloads.
func TestReloadOnSignal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	routes, _ := fakeReloader(t, path, func(int) error { return nil })

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signals := make(chan os.Signal, 1)
	stopped := make(chan struct{})
	go func() {
		reloadOnSignal(ctx, signals, routes)
		close(stopped)
	}()

	signals <- syscall.SIGHUP
	waitFor(t, "the signal to swap in a new router", func() bool { return servedBy(t, routes) == "router-2" })

	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("reloadOnSignal outlived its context")
	}
}

// A refused reload leaves the running router in service, and the loop goes on
// waiting for the signal that fixes it.
func TestReloadOnSignalKeepsServingARefusedReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailgate.hujson")
	routes, _ := fakeReloader(t, path, func(n int) error {
		if n == 2 {
			return errors.New("favicon unreadable")
		}
		return nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	signals := make(chan os.Signal, 1)
	go reloadOnSignal(ctx, signals, routes)

	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP
	waitFor(t, "the second signal to swap in a new router", func() bool { return servedBy(t, routes) == "router-3" })
}

func TestJoinTimeoutFor(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     options
		expected time.Duration
	}{
		{
			name:     "unattended",
			opts:     options{},
			expected: joinTimeout,
		},
		{
			name:     "waiting on a person",
			opts:     options{OpenLoginURL: true},
			expected: interactiveJoinTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := joinTimeoutFor(tc.opts); got != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, got)
			}
		})
	}
}

func TestJoinTailnet(t *testing.T) {
	joinErr := errors.New("funnel attribute missing")

	for _, tc := range []struct {
		name string
		node *fakeNode
		// canceled cancels the parent context, which is the signal that asked
		// tailgate to stop.
		canceled     bool
		expectedFQDN string
		expectedIs   error
		// remedy is whether the error should tell the operator how to join,
		// which only a node that ran out of time needs to be told.
		remedy bool
	}{
		{
			name:         "join reports the node name",
			node:         &fakeNode{fqdn: "tailgate.example.ts.net."},
			expectedFQDN: "tailgate.example.ts.net.",
		},
		{
			name:       "a node that cannot authenticate fails closed",
			node:       &fakeNode{block: true},
			expectedIs: context.DeadlineExceeded,
			remedy:     true,
		},
		{
			name:       "shutdown during a join is not a failed join",
			node:       &fakeNode{block: true},
			canceled:   true,
			expectedIs: context.Canceled,
		},
		{
			name:       "any other join failure passes through",
			node:       &fakeNode{upErr: joinErr},
			expectedIs: joinErr,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			tc.node.steps = &recorder{}

			fqdn, err := joinTailnet(ctx, tc.node, 10*time.Millisecond)

			if fqdn != tc.expectedFQDN {
				t.Errorf("expected fqdn %q, got %q", tc.expectedFQDN, fqdn)
			}
			if tc.expectedIs == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if !errors.Is(err, tc.expectedIs) {
				t.Fatalf("expected error matching %v, got %v", tc.expectedIs, err)
			}
			for _, remedy := range []string{"TS_AUTHKEY", "-open-login"} {
				if strings.Contains(err.Error(), remedy) != tc.remedy {
					t.Errorf("expected mention of %s to be %t in %v", remedy, tc.remedy, err)
				}
			}
		})
	}
}
