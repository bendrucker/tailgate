// Package httptransport reverse-proxies streamable HTTP MCP upstreams.
package httptransport

import (
	"context"
	"errors"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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
	drain           proxy.Drain
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
			// Rewrite drops only the four X-Forwarded headers it knows how to
			// re-set, so the full strip runs here as well as in the router: the
			// no-token-passthrough invariant cannot depend on caller discipline.
			proxy.StripCredentials(r.Out.Header)
			r.Out.Host = target.Host
		},
		// Flush every write immediately so each SSE event reaches the client
		// as soon as the upstream sends it.
		FlushInterval: -1,
		Transport:     dialer,
		ModifyResponse: func(resp *http.Response) error {
			if isEventStream(resp.Header) {
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

// isEventStream reports whether the response is an SSE stream. Media types are
// case-insensitive and may carry parameters, so the header is parsed rather
// than prefix-matched: misreading a stream as a bounded exchange would cut it
// off at the exchange timeout.
func isEventStream(h http.Header) bool {
	mediaType, _, err := mime.ParseMediaType(h.Get("Content-Type"))
	return err == nil && strings.EqualFold(mediaType, "text/event-stream")
}

// ServeHTTP proxies one request. After Shutdown begins it refuses new
// requests with 503 so the listener can drain. Every non-SSE exchange is
// bounded by the exchange timeout; a response identified as SSE runs
// unbounded, per the seam's timeout contract.
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	inflight, err := t.drain.Enter(r.Context())
	if err != nil {
		status := proxy.StatusOf(err)
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer inflight.Done()

	timer := time.AfterFunc(t.exchangeTimeout, func() { inflight.Cancel(proxy.ErrUpstreamTimeout) })
	defer timer.Stop()

	ctx := context.WithValue(inflight.Context(), exchangeTimerKey{}, timer)
	t.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// Shutdown refuses new requests and waits for in-flight requests, including
// open SSE streams, to finish or ctx to expire. On expiry the remaining
// streams are abandoned to Close.
func (t *Transport) Shutdown(ctx context.Context) error {
	return t.drain.Shutdown(ctx)
}

// Close tears down immediately: every in-flight request's context is
// canceled, which aborts active SSE copies and releases their connections,
// and idle upstream connections are closed.
func (t *Transport) Close() error {
	t.drain.Close()
	t.dialer.CloseIdleConnections()
	return nil
}

var _ proxy.Transport = (*Transport)(nil)
