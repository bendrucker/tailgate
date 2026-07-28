package httptransport

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

const sessionID = "sess-1f2e3d4c5b6a"

// mcpUpstream is a minimal streamable-HTTP MCP server (2025-11-25): JSON reply
// to initialize with a minted Mcp-Session-Id, 202 for notifications, an SSE
// stream for tools/call, a standalone GET stream that echoes Last-Event-ID,
// DELETE termination, and 404 for unknown sessions.
type mcpUpstream struct {
	t *testing.T

	// firstEventReceived gates the second tools/call SSE event on the client
	// having consumed the first, proving events stream through the proxy
	// incrementally instead of arriving in one flushed batch.
	firstEventReceived chan struct{}

	mu          sync.Mutex
	seenHeaders []http.Header
}

func (u *mcpUpstream) recordHeaders(r *http.Request) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.seenHeaders = append(u.seenHeaders, r.Header.Clone())
}

func (u *mcpUpstream) checkSession(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Mcp-Session-Id") != sessionID {
		w.WriteHeader(http.StatusNotFound)
		return false
	}
	return true
}

func (u *mcpUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.recordHeaders(r)
	switch r.Method {
	case http.MethodPost:
		u.servePost(w, r)
	case http.MethodGet:
		u.serveGet(w, r)
	case http.MethodDelete:
		if !u.checkSession(w, r) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (u *mcpUpstream) servePost(w http.ResponseWriter, r *http.Request) {
	var msg jsonrpcMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch msg.Method {
	case "initialize":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", sessionID)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%v,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"spike-upstream","version":"0.0.1"}}}`, msg.ID)
	case "notifications/initialized":
		if !u.checkSession(w, r) {
			return
		}
		w.WriteHeader(http.StatusAccepted)
	case "tools/call":
		if !u.checkSession(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl := w.(http.Flusher)
		fmt.Fprint(w, "id: ev-1\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"level\":\"info\",\"data\":\"working\"}}\n\n")
		fl.Flush()
		select {
		case <-u.firstEventReceived:
		case <-time.After(5 * time.Second):
			u.t.Error("client never confirmed the first SSE event; stream is buffering, not streaming")
			return
		}
		fmt.Fprintf(w, "id: ev-2\ndata: {\"jsonrpc\":\"2.0\",\"id\":%v,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"4\"}]}}\n\n", msg.ID)
		fl.Flush()
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (u *mcpUpstream) serveGet(w http.ResponseWriter, r *http.Request) {
	if !u.checkSession(w, r) {
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "id: resume-1\ndata: {\"resumedFrom\":%q}\n\n", r.Header.Get("Last-Event-ID"))
}

type sseEvent struct {
	id   string
	data string
}

func readSSEEvent(t *testing.T, r *bufio.Reader) sseEvent {
	t.Helper()
	var ev sseEvent
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read SSE line: %v", err)
		}
		// SSE permits CRLF line endings, so trim both.
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "":
			return ev
		case strings.HasPrefix(line, "id: "):
			ev.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			ev.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func postMessage(t *testing.T, client *http.Client, endpoint, session, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	// The client's bearer token and spoofed forwarding headers must never
	// reach the upstream.
	req.Header.Set("Authorization", "Bearer super-secret-access-token")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Host", "evil.example.com")
	// ReverseProxy drops only the forwarding headers it can re-set, so these
	// two reach the upstream unless the transport strips them itself.
	req.Header.Set("X-Forwarded-Port", "8443")
	req.Header.Set(proxy.IdentityHeaderPrefix+"Subject", "999")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	return resp
}

func TestEndToEnd(t *testing.T) {
	upstream := &mcpUpstream{t: t, firstEventReceived: make(chan struct{})}
	origin := httptest.NewServer(upstream)
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer transport.Close()

	gateway := httptest.NewServer(transport)
	defer gateway.Close()
	client := gateway.Client()

	var session string
	t.Run("initialize", func(t *testing.T) {
		resp := postMessage(t, client, gateway.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"spike-client","version":"0.0.1"}}}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected application/json, got %q", ct)
		}
		session = resp.Header.Get("Mcp-Session-Id")
		if session != sessionID {
			t.Fatalf("expected upstream session %q preserved, got %q", sessionID, session)
		}
		var msg jsonrpcMessage
		if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
			t.Fatalf("decode initialize result: %v", err)
		}
		var result struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(msg.Result, &result); err != nil {
			t.Fatalf("decode result: %v", err)
		}
		if result.ProtocolVersion != "2025-11-25" {
			t.Errorf("expected protocolVersion 2025-11-25, got %q", result.ProtocolVersion)
		}
	})

	t.Run("initialized notification", func(t *testing.T) {
		resp := postMessage(t, client, gateway.URL, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", resp.StatusCode)
		}
	})

	t.Run("tool call streams over SSE", func(t *testing.T) {
		resp := postMessage(t, client, gateway.URL, session, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add","arguments":{"a":2,"b":2}}}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("expected text/event-stream, got %q", ct)
		}

		reader := bufio.NewReader(resp.Body)
		first := readSSEEvent(t, reader)
		if first.id != "ev-1" {
			t.Errorf("expected event id ev-1 preserved, got %q", first.id)
		}
		if !strings.Contains(first.data, "notifications/message") {
			t.Errorf("expected log notification first, got %q", first.data)
		}
		close(upstream.firstEventReceived)

		second := readSSEEvent(t, reader)
		if second.id != "ev-2" {
			t.Errorf("expected event id ev-2 preserved, got %q", second.id)
		}
		var msg jsonrpcMessage
		if err := json.Unmarshal([]byte(second.data), &msg); err != nil {
			t.Fatalf("decode tool response: %v", err)
		}
		if !strings.Contains(string(msg.Result), `"4"`) {
			t.Errorf("expected tool result 4, got %s", msg.Result)
		}
	})

	t.Run("standalone GET resumes with Last-Event-ID", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, gateway.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("Last-Event-ID", "ev-2")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		ev := readSSEEvent(t, bufio.NewReader(resp.Body))
		if !strings.Contains(ev.data, `"resumedFrom":"ev-2"`) {
			t.Errorf("expected Last-Event-ID to reach upstream, got %q", ev.data)
		}
	})

	t.Run("unknown session maps to 404", func(t *testing.T) {
		resp := postMessage(t, client, gateway.URL, "sess-forged", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", resp.StatusCode)
		}
	})

	t.Run("delete terminates session", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, gateway.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Mcp-Session-Id", session)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("DELETE: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", resp.StatusCode)
		}
	})

	t.Run("upstream never sees credentials or forwarding headers", func(t *testing.T) {
		upstream.mu.Lock()
		defer upstream.mu.Unlock()
		if len(upstream.seenHeaders) == 0 {
			t.Fatal("upstream saw no requests")
		}
		for _, h := range upstream.seenHeaders {
			for _, banned := range []string{
				"Authorization",
				"X-Forwarded-For",
				"X-Forwarded-Host",
				"X-Forwarded-Proto",
				"X-Forwarded-Port",
				proxy.IdentityHeaderPrefix + "Subject",
			} {
				if v := h.Get(banned); v != "" {
					t.Errorf("upstream saw %s: %q", banned, v)
				}
			}
		}
	})
}

func TestUpstreamUnreachable(t *testing.T) {
	target, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer transport.Close()
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	resp := postMessage(t, gateway.Client(), gateway.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestShutdownDrains(t *testing.T) {
	release := make(chan struct{})
	arrived := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case arrived <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusAccepted)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer transport.Close()
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	inflightDone := make(chan int, 1)
	go func() {
		resp := postMessage(t, gateway.Client(), gateway.URL, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		defer resp.Body.Close()
		inflightDone <- resp.StatusCode
	}()

	// Wait until the in-flight request reaches the blocked upstream so
	// Shutdown observes it.
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never reached upstream")
	}

	// An already-expired context makes Shutdown mark the transport draining
	// and return immediately, so the 503 refusal can be asserted with one
	// deterministic request.
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	if err := transport.Shutdown(expired); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from expired drain, got %v", err)
	}

	resp := postMessage(t, gateway.Client(), gateway.URL, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during drain, got %d", resp.StatusCode)
	}

	close(release)
	if err := transport.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if status := <-inflightDone; status != http.StatusAccepted {
		t.Fatalf("in-flight request should complete during drain, got %d", status)
	}
}

func TestPathedTargetPreservesEndpointPath(t *testing.T) {
	paths := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths <- r.URL.Path
		w.WriteHeader(http.StatusAccepted)
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL + "/mcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer transport.Close()
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	resp := postMessage(t, gateway.Client(), gateway.URL, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	resp.Body.Close()
	if got := <-paths; got != "/mcp" {
		t.Fatalf("expected upstream path /mcp, got %q", got)
	}
}

func TestCloseAbandonsStream(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "id: ev-1\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	req, err := http.NewRequest(http.MethodGet, gateway.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := gateway.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	readSSEEvent(t, bufio.NewReader(resp.Body))

	closed := make(chan error, 1)
	go func() { closed <- transport.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not sever the active stream")
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("expected the abandoned stream to error for the client")
	}
}

func TestExchangeTimeout(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body first: the server arms its disconnect watcher only
		// once the request body reaches EOF, and a real upstream reads what
		// it is sent.
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Error("upstream was never released by the exchange timeout")
		}
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer transport.Close()
	transport.exchangeTimeout = 50 * time.Millisecond
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	resp := postMessage(t, gateway.Client(), gateway.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504 for a stalled non-SSE exchange, got %d", resp.StatusCode)
	}
}

func TestSSEExemptFromExchangeTimeout(t *testing.T) {
	// Media types are case-insensitive and may carry parameters, so every
	// spelling of text/event-stream must survive past the exchange timeout.
	for _, tc := range []struct {
		name        string
		contentType string
	}{
		{
			name:        "canonical spelling",
			contentType: "text/event-stream",
		},
		{
			name:        "mixed case",
			contentType: "Text/Event-Stream",
		},
		{
			name:        "charset parameter",
			contentType: "TEXT/EVENT-STREAM; charset=utf-8",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(http.StatusOK)
				fl := w.(http.Flusher)
				fmt.Fprint(w, "id: ev-1\ndata: {}\n\n")
				fl.Flush()
				time.Sleep(300 * time.Millisecond)
				fmt.Fprint(w, "id: ev-2\ndata: {}\n\n")
				fl.Flush()
			}))
			defer origin.Close()

			target, err := url.Parse(origin.URL)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			transport := New(target, slog.New(slog.NewTextHandler(io.Discard, nil)))
			defer transport.Close()
			transport.exchangeTimeout = 75 * time.Millisecond
			gateway := httptest.NewServer(transport)
			defer gateway.Close()

			req, err := http.NewRequest(http.MethodGet, gateway.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("Accept", "text/event-stream")
			resp, err := gateway.Client().Do(req)
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()

			reader := bufio.NewReader(resp.Body)
			if ev := readSSEEvent(t, reader); ev.id != "ev-1" {
				t.Fatalf("expected ev-1, got %q", ev.id)
			}
			// The stream outlives the exchange timeout because ModifyResponse
			// stops the timer for SSE responses.
			if ev := readSSEEvent(t, reader); ev.id != "ev-2" {
				t.Fatalf("expected ev-2 after the timeout window, got %q", ev.id)
			}
		})
	}
}

func TestClientAbortIsNotAnUpstreamError(t *testing.T) {
	arrived := make(chan struct{}, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case arrived <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Error("upstream never observed the client abort")
		}
	}))
	defer origin.Close()

	target, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var logs strings.Builder
	transport := New(target, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer transport.Close()
	gateway := httptest.NewServer(transport)
	defer gateway.Close()

	ctx, cancel := context.WithCancel(t.Context())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.URL, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	errs := make(chan error, 1)
	go func() {
		resp, err := gateway.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
		errs <- err
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("request never reached upstream")
	}
	cancel()
	if err := <-errs; err == nil {
		t.Fatal("expected the aborted request to error")
	}

	// Drain so the proxy's error handling has finished before reading logs.
	if err := transport.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if strings.Contains(logs.String(), "upstream proxy error") {
		t.Fatalf("client abort logged as upstream error:\n%s", logs.String())
	}
}
