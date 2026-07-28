// Package httptransport reverse-proxies streamable HTTP MCP upstreams.
package httptransport

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// Transport proxies one upstream's MCP endpoint. The upstream owns the
// protocol: it mints Mcp-Session-Id, chooses JSON or SSE per POST, and
// numbers SSE events. The proxy's job is fidelity, so session headers and SSE
// bytes (event ids, retry fields, framing) pass through unmodified and
// unbuffered.
type Transport struct {
	proxy    *httputil.ReverseProxy
	dialer   *http.Transport
	inflight sync.WaitGroup

	mu       sync.Mutex
	draining bool
}

// New returns a Transport proxying to the upstream MCP endpoint at target.
// Construction never dials; an unreachable upstream surfaces per-request as
// 502.
func New(target *url.URL, logger *slog.Logger) *Transport {
	dialer := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		// SSE responses must not be transparently decompressed: re-encoding
		// would break byte fidelity and buffering would stall the stream.
		DisableCompression: true,
	}

	t := &Transport{dialer: dialer}
	t.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// The router already strips these, and Rewrite drops inbound
			// X-Forwarded-*, but the no-token-passthrough invariant is
			// enforced here too so it cannot depend on caller discipline.
			r.Out.Header.Del("Authorization")
			r.Out.Host = target.Host
		},
		// Flush every write immediately so each SSE event reaches the client
		// as soon as the upstream sends it.
		FlushInterval: -1,
		Transport:     dialer,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream proxy error", "err", err, "method", r.Method)
			w.WriteHeader(proxy.StatusOf(proxy.ErrUpstreamUnavailable))
		},
	}
	return t
}

// ServeHTTP proxies one request. After Shutdown begins it refuses new
// requests with 503 so the listener can drain.
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t.mu.Lock()
	if t.draining {
		t.mu.Unlock()
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	t.inflight.Add(1)
	t.mu.Unlock()
	defer t.inflight.Done()

	t.proxy.ServeHTTP(w, r)
}

// Shutdown refuses new requests and waits for in-flight requests, including
// open SSE streams, to finish or ctx to expire. On expiry the remaining
// streams are abandoned to Close.
func (t *Transport) Shutdown(ctx context.Context) error {
	t.mu.Lock()
	t.draining = true
	t.mu.Unlock()

	done := make(chan struct{})
	go func() {
		t.inflight.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down idle upstream connections immediately. In-flight requests
// are interrupted by the server closing their client connections, not here.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.draining = true
	t.mu.Unlock()
	t.dialer.CloseIdleConnections()
	return nil
}

var _ proxy.Transport = (*Transport)(nil)
