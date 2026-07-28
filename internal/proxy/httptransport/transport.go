// Package httptransport reverse-proxies streamable HTTP MCP upstreams.
package httptransport

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// defaultExchangeTimeout bounds a complete non-SSE exchange: writing the
// request, waiting for headers, and reading the body. SSE streams are exempt
// once their content type is known.
const defaultExchangeTimeout = time.Minute

// Transport proxies one upstream's MCP endpoint. The upstream owns the
// protocol: it mints Mcp-Session-Id, chooses JSON or SSE per POST, and
// numbers SSE events. The proxy's job is fidelity, so session headers and SSE
// bytes (event ids, retry fields, framing) pass through unmodified and
// unbuffered.
type Transport struct {
	proxy           *httputil.ReverseProxy
	dialer          *http.Transport
	exchangeTimeout time.Duration
	inflight        sync.WaitGroup

	mu       sync.Mutex
	draining bool
	cancels  map[uint64]context.CancelCauseFunc
	nextID   uint64
}

type exchangeTimerKey struct{}

// New returns a Transport proxying to the upstream MCP endpoint at target.
// Construction never dials. An unreachable upstream surfaces per-request as
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

	t := &Transport{
		dialer:          dialer,
		exchangeTimeout: defaultExchangeTimeout,
		cancels:         make(map[uint64]context.CancelCauseFunc),
	}
	t.proxy = &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// SetURL joins the target path with the inbound "/", turning a
			// target of /mcp into /mcp/, which exact-path upstream routers
			// reject. The router already rewrote the request to the endpoint
			// root, so the outbound path is exactly the target's.
			r.Out.URL.Path = target.Path
			r.Out.URL.RawPath = target.RawPath
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
		ModifyResponse: func(resp *http.Response) error {
			if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
				if timer, ok := resp.Request.Context().Value(exchangeTimerKey{}).(*time.Timer); ok {
					timer.Stop()
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cause := context.Cause(r.Context())
			switch {
			case errors.Is(cause, proxy.ErrUpstreamTimeout):
				logger.Error("upstream exchange timed out", "method", r.Method)
				w.WriteHeader(proxy.StatusOf(proxy.ErrUpstreamTimeout))
			case r.Context().Err() != nil:
				// The client went away (or Close abandoned the request):
				// nothing is wrong with the upstream and there is no one
				// left to answer.
				logger.Debug("request canceled", "cause", cause)
			default:
				logger.Error("upstream proxy error", "err", err, "method", r.Method)
				w.WriteHeader(proxy.StatusOf(proxy.ErrUpstreamUnavailable))
			}
		},
	}
	return t
}

// ServeHTTP proxies one request. After Shutdown begins it refuses new
// requests with 503 so the listener can drain. Every non-SSE exchange is
// bounded by the exchange timeout; a response identified as SSE runs
// unbounded, per the seam's timeout contract.
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithCancelCause(r.Context())
	t.mu.Lock()
	if t.draining {
		t.mu.Unlock()
		cancel(nil)
		http.Error(w, proxy.ErrDraining.Error(), proxy.StatusOf(proxy.ErrDraining))
		return
	}
	t.inflight.Add(1)
	id := t.nextID
	t.nextID++
	t.cancels[id] = cancel
	t.mu.Unlock()

	timer := time.AfterFunc(t.exchangeTimeout, func() { cancel(proxy.ErrUpstreamTimeout) })

	defer func() {
		timer.Stop()
		cancel(nil)
		t.mu.Lock()
		delete(t.cancels, id)
		t.mu.Unlock()
		t.inflight.Done()
	}()

	ctx = context.WithValue(ctx, exchangeTimerKey{}, timer)
	t.proxy.ServeHTTP(w, r.WithContext(ctx))
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

// Close tears down immediately: every in-flight request's context is
// canceled, which aborts active SSE copies and releases their connections,
// and idle upstream connections are closed.
func (t *Transport) Close() error {
	t.mu.Lock()
	t.draining = true
	cancels := make([]context.CancelCauseFunc, 0, len(t.cancels))
	for _, cancel := range t.cancels {
		cancels = append(cancels, cancel)
	}
	t.mu.Unlock()

	for _, cancel := range cancels {
		cancel(proxy.ErrDraining)
	}
	t.inflight.Wait()
	t.dialer.CloseIdleConnections()
	return nil
}

var _ proxy.Transport = (*Transport)(nil)
