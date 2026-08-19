package tsnetserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

// fakeNode stands in for tsnet.Server. Joining a real tailnet needs a control
// server, so the tests drive the lifecycle around tsnet through this.
type fakeNode struct {
	up        func(context.Context) (*ipnstate.Status, error)
	listen    func(network, addr string) (net.Listener, error)
	client    *http.Client
	closeErr  error
	listenErr error

	mu          sync.Mutex
	upCalls     int
	closeCalls  int
	listenCalls []string
	events      []string
}

func (f *fakeNode) Up(ctx context.Context) (*ipnstate.Status, error) {
	f.mu.Lock()
	f.upCalls++
	f.mu.Unlock()
	if f.up == nil {
		return joinedStatus("fake.tail-scale.ts.net."), nil
	}
	return f.up(ctx)
}

func (f *fakeNode) ListenFunnel(network, addr string, _ ...tsnet.FunnelOption) (net.Listener, error) {
	f.mu.Lock()
	f.listenCalls = append(f.listenCalls, network+" "+addr)
	f.mu.Unlock()
	if f.listenErr != nil {
		return nil, f.listenErr
	}
	listen := f.listen
	if listen == nil {
		listen = func(network, _ string) (net.Listener, error) { return net.Listen(network, "127.0.0.1:0") }
	}
	ln, err := listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &recordingListener{Listener: ln, record: f.record}, nil
}

func (f *fakeNode) HTTPClient() *http.Client { return f.client }

func (f *fakeNode) Close() error {
	f.mu.Lock()
	f.closeCalls++
	f.mu.Unlock()
	f.record("node closed")
	return f.closeErr
}

func (f *fakeNode) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *fakeNode) recorded() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func (f *fakeNode) counts() (up, closes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upCalls, f.closeCalls
}

type recordingListener struct {
	net.Listener
	record func(string)
}

func (l *recordingListener) Close() error {
	l.record("listener closed")
	return l.Listener.Close()
}

// errListener fails every Close, standing in for a listener whose teardown
// reports a real fault rather than an already-closed socket.
type errListener struct {
	net.Listener
	err error
}

func (l *errListener) Close() error {
	l.Listener.Close()
	return l.err
}

func joinedStatus(dnsName string) *ipnstate.Status {
	return &ipnstate.Status{Self: &ipnstate.PeerStatus{DNSName: dnsName}}
}

func staticUp(status *ipnstate.Status, err error) func(context.Context) (*ipnstate.Status, error) {
	return func(context.Context) (*ipnstate.Status, error) { return status, err }
}

func TestNew(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         Config
		wantAddr    string
		wantErrText string
	}{
		{
			name:     "funnel port 443",
			cfg:      Config{Hostname: "tailgate", Port: 443},
			wantAddr: ":443",
		},
		{
			name:     "funnel port 8443",
			cfg:      Config{Hostname: "tailgate", Port: 8443},
			wantAddr: ":8443",
		},
		{
			name:     "funnel port 10000",
			cfg:      Config{Hostname: "tailgate", Port: 10000},
			wantAddr: ":10000",
		},
		{
			name:        "plain http port rejected",
			cfg:         Config{Hostname: "tailgate", Port: 80},
			wantErrText: "port 80 is not a Funnel port",
		},
		{
			name:        "near miss port rejected",
			cfg:         Config{Hostname: "tailgate", Port: 8080},
			wantErrText: "port 8080 is not a Funnel port",
		},
		{
			name:        "unset port rejected",
			cfg:         Config{Hostname: "tailgate"},
			wantErrText: "port 0 is not a Funnel port",
		},
		{
			name:        "out of range port rejected",
			cfg:         Config{Hostname: "tailgate", Port: 70000},
			wantErrText: "port 70000 is not a Funnel port",
		},
		{
			name:        "missing hostname rejected",
			cfg:         Config{Port: 443},
			wantErrText: "hostname is required",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(tc.cfg)
			if tc.wantErrText != "" {
				if err == nil {
					t.Fatalf("New(%+v) = nil error, want %q", tc.cfg, tc.wantErrText)
				}
				if !strings.Contains(err.Error(), tc.wantErrText) {
					t.Fatalf("New error = %q, want it to contain %q", err, tc.wantErrText)
				}
				if srv != nil {
					t.Errorf("New returned a server alongside an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%+v) = %v", tc.cfg, err)
			}
			if srv.addr != tc.wantAddr {
				t.Errorf("listen addr = %q, want %q", srv.addr, tc.wantAddr)
			}
		})
	}
}

// TestNewAdvertisesTags covers the plumbing that puts the node's tailnet
// identity in the config rather than leaving it implicit in whichever auth key
// minted the node.
func TestNewAdvertisesTags(t *testing.T) {
	for _, tc := range []struct {
		name string
		tags []string
	}{
		{name: "no tags advertises none"},
		{name: "one tag", tags: []string{"tag:tailgate"}},
		{name: "several tags", tags: []string{"tag:tailgate", "tag:mcp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(Config{Hostname: "tailgate", Port: 443, Tags: tc.tags})
			if err != nil {
				t.Fatalf("New = %v", err)
			}
			node, ok := srv.node.(*tsnet.Server)
			if !ok {
				t.Fatalf("New built a %T, want a *tsnet.Server", srv.node)
			}
			if diff := cmp.Diff(tc.tags, node.AdvertiseTags); diff != "" {
				t.Errorf("advertised tags (-want +got):\n%s", diff)
			}
		})
	}
}

func TestServerUp(t *testing.T) {
	blockUntilDone := func(ctx context.Context) (*ipnstate.Status, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("tsnet: %w", ctx.Err())
	}

	for _, tc := range []struct {
		name        string
		up          func(context.Context) (*ipnstate.Status, error)
		timeout     time.Duration
		wantFQDN    string
		wantErrIs   error
		wantErrText string
	}{
		{
			name:     "join reports the tailnet name",
			up:       staticUp(joinedStatus("tailgate.tail-scale.ts.net."), nil),
			wantFQDN: "tailgate.tail-scale.ts.net.",
		},
		{
			name:        "join failure surfaces",
			up:          staticUp(nil, errors.New("control server unreachable")),
			wantErrText: "join tailnet: control server unreachable",
		},
		{
			name:        "deadline surfaces as a context error",
			up:          blockUntilDone,
			timeout:     20 * time.Millisecond,
			wantErrIs:   context.DeadlineExceeded,
			wantErrText: "did not join the tailnet in time",
		},
		{
			name:        "missing status is an error",
			up:          staticUp(nil, nil),
			wantErrText: "without a tailnet DNS name",
		},
		{
			name:        "status without self is an error",
			up:          staticUp(&ipnstate.Status{}, nil),
			wantErrText: "without a tailnet DNS name",
		},
		{
			name:        "empty dns name is an error",
			up:          staticUp(joinedStatus(""), nil),
			wantErrText: "without a tailnet DNS name",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(&fakeNode{up: tc.up}, 443)

			ctx := context.Background()
			if tc.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.timeout)
				defer cancel()
			}

			fqdn, err := srv.Up(ctx)
			if tc.wantErrText == "" && tc.wantErrIs == nil {
				if err != nil {
					t.Fatalf("Up = %v", err)
				}
				if fqdn != tc.wantFQDN {
					t.Errorf("FQDN = %q, want %q", fqdn, tc.wantFQDN)
				}
				if got := srv.FQDN(); got != tc.wantFQDN {
					t.Errorf("cached FQDN = %q, want %q", got, tc.wantFQDN)
				}
				return
			}
			if err == nil {
				t.Fatalf("Up = %q, want an error", fqdn)
			}
			if fqdn != "" {
				t.Errorf("Up returned FQDN %q alongside an error", fqdn)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("Up error = %v, want errors.Is %v", err, tc.wantErrIs)
			}
			if tc.wantErrText != "" && !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("Up error = %q, want it to contain %q", err, tc.wantErrText)
			}
			if got := srv.FQDN(); got != "" {
				t.Errorf("FQDN = %q after a failed join, want empty", got)
			}
		})
	}
}

func TestServerUpJoinsOnce(t *testing.T) {
	node := &fakeNode{up: staticUp(joinedStatus("tailgate.tail-scale.ts.net."), nil)}
	srv := newServer(node, 443)

	first, err := srv.Up(context.Background())
	if err != nil {
		t.Fatalf("first Up = %v", err)
	}
	second, err := srv.Up(context.Background())
	if err != nil {
		t.Fatalf("second Up = %v", err)
	}
	if first != second {
		t.Errorf("Up returned %q then %q, want the same name", first, second)
	}
	if ups, _ := node.counts(); ups != 1 {
		t.Errorf("node.Up called %d times, want 1", ups)
	}
}

// Up releases the lock across the join so shutdown never waits on control,
// which lets Close complete while a join is still in flight.
func TestServerUpAfterConcurrentClose(t *testing.T) {
	joining := make(chan struct{})
	closed := make(chan struct{})
	node := &fakeNode{up: func(context.Context) (*ipnstate.Status, error) {
		close(joining)
		<-closed
		return joinedStatus("tailgate.tail-scale.ts.net."), nil
	}}
	srv := newServer(node, 443)

	upErr := make(chan error, 1)
	go func() {
		_, err := srv.Up(context.Background())
		upErr <- err
	}()

	<-joining
	if err := srv.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	close(closed)

	if err := <-upErr; !errors.Is(err, ErrClosed) {
		t.Errorf("Up = %v, want ErrClosed: a join that lands after Close must not report a live node", err)
	}
	if got := srv.FQDN(); got != "" {
		t.Errorf("FQDN = %q, want empty on a closed server", got)
	}
}

func TestListenFunnelAccepts(t *testing.T) {
	node := &fakeNode{}
	srv := newServer(node, 8443)

	ln, err := srv.ListenFunnel()
	if err != nil {
		t.Fatalf("ListenFunnel = %v", err)
	}
	if diff := cmp.Diff([]string{"tcp :8443"}, node.listenCalls); diff != "" {
		t.Errorf("funnel listen call (-want +got):\n%s", diff)
	}

	httpSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go httpSrv.Serve(ln)
	t.Cleanup(func() { httpSrv.Close() })

	// Keep-alives would let the post-shutdown request ride the connection the
	// first one opened, testing nothing about accepting.
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := client.Get("http://" + ln.Addr().String())
	if err != nil {
		t.Fatalf("request through the funnel listener = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	addr := ln.Addr().String()
	if err := srv.StopAccepting(); err != nil {
		t.Fatalf("StopAccepting = %v", err)
	}
	if _, err := client.Get("http://" + addr); err == nil {
		t.Errorf("request succeeded after StopAccepting, want a connection failure")
	}
}

func TestListenFunnelStartsOnce(t *testing.T) {
	srv := newServer(&fakeNode{}, 443)
	if _, err := srv.ListenFunnel(); err != nil {
		t.Fatalf("ListenFunnel = %v", err)
	}
	_, err := srv.ListenFunnel()
	if err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("second ListenFunnel = %v, want an already-started error", err)
	}
}

func TestListenFunnelError(t *testing.T) {
	srv := newServer(&fakeNode{listenErr: errors.New("funnel not enabled for this node")}, 443)
	ln, err := srv.ListenFunnel()
	if err == nil {
		t.Fatalf("ListenFunnel = %v, want an error", ln)
	}
	if !strings.Contains(err.Error(), "listen funnel on :443") {
		t.Errorf("error = %q, want it to name the funnel address", err)
	}
	// A failed listen leaves nothing tracked, so a retry is allowed.
	if srv.listener != nil {
		t.Errorf("failed ListenFunnel tracked a listener")
	}
}

func TestServerShutdown(t *testing.T) {
	for _, tc := range []struct {
		name           string
		serve          bool
		shutdown       func(*Server) error
		wantEvents     []string
		wantCloseCalls int
	}{
		{
			name:  "stop accepting precedes node close",
			serve: true,
			shutdown: func(s *Server) error {
				return errors.Join(s.StopAccepting(), s.Close())
			},
			wantEvents:     []string{"listener closed", "node closed"},
			wantCloseCalls: 1,
		},
		{
			name:  "close stops the listener first",
			serve: true,
			shutdown: func(s *Server) error {
				return s.Close()
			},
			wantEvents:     []string{"listener closed", "node closed"},
			wantCloseCalls: 1,
		},
		{
			name:  "double close closes the node once",
			serve: true,
			shutdown: func(s *Server) error {
				return errors.Join(s.Close(), s.Close())
			},
			wantEvents:     []string{"listener closed", "node closed"},
			wantCloseCalls: 1,
		},
		{
			name:  "double stop accepting closes the listener once",
			serve: true,
			shutdown: func(s *Server) error {
				return errors.Join(s.StopAccepting(), s.StopAccepting())
			},
			wantEvents:     []string{"listener closed"},
			wantCloseCalls: 0,
		},
		{
			name:  "stop accepting before serve is a no-op",
			serve: false,
			shutdown: func(s *Server) error {
				return s.StopAccepting()
			},
			wantCloseCalls: 0,
		},
		{
			name:  "close before serve closes the node",
			serve: false,
			shutdown: func(s *Server) error {
				return s.Close()
			},
			wantEvents:     []string{"node closed"},
			wantCloseCalls: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := &fakeNode{}
			srv := newServer(node, 443)
			if tc.serve {
				if _, err := srv.ListenFunnel(); err != nil {
					t.Fatalf("ListenFunnel = %v", err)
				}
			}

			if err := tc.shutdown(srv); err != nil {
				t.Fatalf("shutdown = %v", err)
			}
			if diff := cmp.Diff(tc.wantEvents, node.recorded()); diff != "" {
				t.Errorf("shutdown sequence (-want +got):\n%s", diff)
			}
			if _, closes := node.counts(); closes != tc.wantCloseCalls {
				t.Errorf("node.Close called %d times, want %d", closes, tc.wantCloseCalls)
			}
		})
	}
}

func TestShutdownErrors(t *testing.T) {
	for _, tc := range []struct {
		name        string
		node        *fakeNode
		wantErrText []string
	}{
		{
			name: "node close failure surfaces",
			node: &fakeNode{closeErr: errors.New("node teardown failed")},
			wantErrText: []string{
				"close node: node teardown failed",
			},
		},
		{
			name: "listener close failure surfaces",
			node: &fakeNode{listen: func(network, _ string) (net.Listener, error) {
				ln, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				return &errListener{Listener: ln, err: errors.New("listener teardown failed")}, nil
			}},
			wantErrText: []string{
				"stop funnel listener: listener teardown failed",
			},
		},
		{
			name: "an already closed listener is not an error",
			node: &fakeNode{listen: func(network, _ string) (net.Listener, error) {
				ln, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					return nil, err
				}
				return &errListener{Listener: ln, err: net.ErrClosed}, nil
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(tc.node, 443)
			if _, err := srv.ListenFunnel(); err != nil {
				t.Fatalf("ListenFunnel = %v", err)
			}

			err := srv.Close()
			if len(tc.wantErrText) == 0 {
				if err != nil {
					t.Fatalf("Close = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Close = nil, want an error")
			}
			for _, want := range tc.wantErrText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Close error = %q, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestAfterClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*Server) error
	}{
		{
			name: "up",
			call: func(s *Server) error {
				_, err := s.Up(context.Background())
				return err
			},
		},
		{
			name: "listen funnel",
			call: func(s *Server) error {
				_, err := s.ListenFunnel()
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(&fakeNode{}, 443)
			if err := srv.Close(); err != nil {
				t.Fatalf("Close = %v", err)
			}
			if err := tc.call(srv); !errors.Is(err, ErrClosed) {
				t.Errorf("call after Close = %v, want %v", err, ErrClosed)
			}
		})
	}
}

func TestHTTPClient(t *testing.T) {
	client := &http.Client{}
	srv := newServer(&fakeNode{client: client}, 443)
	if got := srv.HTTPClient(); got != client {
		t.Errorf("HTTPClient = %p, want the node's client %p", got, client)
	}
}
