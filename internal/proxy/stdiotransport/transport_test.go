package stdiotransport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/auth"
	"github.com/bendrucker/tailgate/internal/protocol"
	"github.com/google/go-cmp/cmp"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeChildEnv) != "" {
		runFakeChild()
		return
	}
	os.Exit(m.Run())
}

// Headers standing in for the router, which is what puts an authorized
// identity in the request context. blankIdentityHeader covers the routing
// fault the transport must fail closed on: an identity present but carrying no
// subject.
const (
	subjectHeader       = "X-Test-Subject"
	blankIdentityHeader = "X-Test-Blank-Identity"
)

const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{}}}`

type harness struct {
	transport *Transport
	gateway   *httptest.Server
	audit     *auditCollector
}

func newHarness(t *testing.T, options Options) *harness {
	t.Helper()
	if options.Command == "" {
		options.Command = os.Args[0]
	}
	options.Env = append(options.Env, fakeChildEnv+"=1")
	if options.Logger == nil {
		options.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	decisions := &auditCollector{}
	options.Audit = audit.New(slog.New(decisions))

	transport := New(options)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subject := r.Header.Get(subjectHeader); subject != "" {
			identity := auth.Identity{Subject: subject, Email: subject + "@example.com"}
			r = r.WithContext(auth.WithIdentity(r.Context(), identity))
		} else if r.Header.Get(blankIdentityHeader) != "" {
			r = r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{}))
		}
		transport.ServeHTTP(w, r)
	}))
	t.Cleanup(func() {
		gateway.Close()
		if err := transport.Close(); err != nil {
			t.Errorf("close transport: %v", err)
		}
	})
	return &harness{transport: transport, gateway: gateway, audit: decisions}
}

// auditRecord is one decision as the audit package rendered it.
type auditRecord struct {
	Level    string
	Outcome  string
	Subject  string
	Email    string
	Upstream string
	Reason   string
	Rule     string
}

type auditCollector struct {
	mu      sync.Mutex
	records []auditRecord
}

func (c *auditCollector) Enabled(context.Context, slog.Level) bool { return true }

func (c *auditCollector) Handle(_ context.Context, r slog.Record) error {
	if r.Message != audit.Message {
		return nil
	}
	record := auditRecord{Level: r.Level.String()}
	r.Attrs(func(a slog.Attr) bool {
		switch a.Key {
		case audit.KeyOutcome:
			record.Outcome = a.Value.String()
		case audit.KeySubject:
			record.Subject = a.Value.String()
		case audit.KeyEmail:
			record.Email = a.Value.String()
		case audit.KeyUpstream:
			record.Upstream = a.Value.String()
		case audit.KeyReason:
			record.Reason = a.Value.String()
		case audit.KeyRule:
			record.Rule = a.Value.String()
		}
		return true
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
	return nil
}

func (c *auditCollector) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *auditCollector) WithGroup(string) slog.Handler      { return c }

func (c *auditCollector) decisions() []auditRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]auditRecord(nil), c.records...)
}

type call struct {
	method        string
	subject       string
	blankIdentity bool
	session       string
	protocol      string
	body          string
	// ctx stands in for the client's own lifetime. A call carrying one may be
	// abandoned before its answer, and do reports that as a nil response rather
	// than a failure.
	ctx context.Context
}

func (h *harness) do(t *testing.T, c call) *http.Response {
	t.Helper()
	method := c.method
	if method == "" {
		method = http.MethodPost
	}
	var body io.Reader
	if c.body != "" {
		body = strings.NewReader(c.body)
	}
	ctx := c.ctx
	if ctx == nil {
		ctx = t.Context()
	}
	request, err := http.NewRequestWithContext(ctx, method, h.gateway.URL, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	if c.subject != "" {
		request.Header.Set(subjectHeader, c.subject)
	}
	if c.blankIdentity {
		request.Header.Set(blankIdentityHeader, "1")
	}
	if c.session != "" {
		request.Header.Set(sessionHeader, c.session)
	}
	if c.protocol != "" {
		request.Header.Set(protocolVersionHeader, c.protocol)
	}
	response, err := h.gateway.Client().Do(request)
	if err != nil {
		if c.ctx != nil && c.ctx.Err() != nil {
			return nil
		}
		t.Fatalf("%s: %v", method, err)
	}
	return response
}

// initialize opens a session for subject and returns its minted id.
func (h *harness) initialize(t *testing.T, subject string) string {
	t.Helper()
	response := h.do(t, call{subject: subject, body: initializeBody})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("initialize: expected 200, got %d", response.StatusCode)
	}
	session := response.Header.Get(sessionHeader)
	if session == "" {
		t.Fatal("initialize response carried no Mcp-Session-Id")
	}
	return session
}

func requestBody(id int, method, echo string, delay time.Duration) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{"echo":%q,"delay_ms":%d}}`, id, method, echo, delay.Milliseconds())
}

func decodeMessage(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	var message map[string]any
	if err := json.NewDecoder(response.Body).Decode(&message); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return message
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (t *Transport) sessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// listenerCount reports the subscription streams open across every session,
// which is what a slot leaked by an abandoned stream shows up in.
func (t *Transport) listenerCount() int {
	t.mu.Lock()
	sessions := slices.Collect(maps.Values(t.sessions))
	t.mu.Unlock()

	count := 0
	for _, s := range sessions {
		s.mu.Lock()
		count += len(s.listeners)
		s.mu.Unlock()
	}
	return count
}

// pendingRequests reports the waiters registered across every live session,
// which is how a test sees a request reach the child and an abandoned one
// leave the correlation map.
func (t *Transport) pendingRequests() int {
	t.mu.Lock()
	sessions := slices.Collect(maps.Values(t.sessions))
	t.mu.Unlock()

	total := 0
	for _, s := range sessions {
		s.mu.Lock()
		total += len(s.pending)
		s.mu.Unlock()
	}
	return total
}

// reservedSlots reports the cap slots subject currently holds, which is what a
// leaked reservation shows up in.
func (t *Transport) reservedSlots(subject string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.perIdentity[subject]
}

func TestInitializeMintsBoundSession(t *testing.T) {
	h := newHarness(t, Options{})

	response := h.do(t, call{subject: "alice", body: initializeBody})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected application/json, got %q", contentType)
	}

	session := response.Header.Get(sessionHeader)
	if len(session) < 32 {
		t.Errorf("expected a long random session id, got %q", session)
	}
	for _, r := range session {
		if r < 0x21 || r > 0x7e {
			t.Fatalf("session id %q contains non-visible-ASCII %q", session, r)
		}
	}

	message := decodeMessage(t, response)
	if message["id"] != float64(1) {
		t.Errorf("expected the initialize id echoed, got %v", message["id"])
	}
	result, _ := message["result"].(map[string]any)
	if result["protocolVersion"] != "2025-11-25" {
		t.Errorf("expected the child's initialize result, got %v", message)
	}

	h.transport.mu.Lock()
	defer h.transport.mu.Unlock()
	if bound := h.transport.sessions[session]; bound == nil || bound.subject != "alice" {
		t.Fatal("session was not registered against the initializing identity")
	}
}

func TestSessionBoundToIdentity(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	for _, tc := range []struct {
		name     string
		subject  string
		expected int
	}{
		{
			name:     "owner reaches the session",
			subject:  "alice",
			expected: http.StatusOK,
		},
		{
			name:     "another identity gets not found",
			subject:  "mallory",
			expected: http.StatusNotFound,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.do(t, call{subject: tc.subject, session: session, body: requestBody(2, "tools/list", "", 0)})
			defer response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, response.StatusCode)
			}
		})
	}
}

func TestSessionLookupFailures(t *testing.T) {
	h := newHarness(t, Options{})
	h.initialize(t, "alice")

	for _, tc := range []struct {
		name     string
		call     call
		expected int
	}{
		{
			name:     "missing session header",
			call:     call{subject: "alice", body: requestBody(2, "tools/list", "", 0)},
			expected: http.StatusBadRequest,
		},
		{
			name:     "unknown session",
			call:     call{subject: "alice", session: "not-a-session", body: requestBody(2, "tools/list", "", 0)},
			expected: http.StatusNotFound,
		},
		{
			name:     "unknown session on delete",
			call:     call{method: http.MethodDelete, subject: "alice", session: "not-a-session"},
			expected: http.StatusNotFound,
		},
		{
			name:     "missing session header on delete",
			call:     call{method: http.MethodDelete, subject: "alice"},
			expected: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.do(t, tc.call)
			defer response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, response.StatusCode)
			}
		})
	}
}

func TestConcurrentRequestsCorrelateByID(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	const requests = 24
	var wg sync.WaitGroup
	results := make([]map[string]any, requests)
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Later requests answer sooner, so a transport that paired
			// responses by arrival order would mismatch every one of them.
			delay := time.Duration(requests-i) * 2 * time.Millisecond
			id := i + 100
			response := h.do(t, call{
				subject: "alice",
				session: session,
				body:    requestBody(id, "tools/call", fmt.Sprintf("echo-%d", id), delay),
			})
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", id, response.StatusCode)
				return
			}
			results[i] = decodeMessage(t, response)
		}()
	}
	wg.Wait()

	for i, message := range results {
		id := i + 100
		expected := map[string]any{
			"jsonrpc": "2.0",
			"id":      float64(id),
			"result": map[string]any{
				"method": "tools/call",
				"echo":   fmt.Sprintf("echo-%d", id),
			},
		}
		if diff := cmp.Diff(expected, message); diff != "" {
			t.Errorf("request %d got the wrong response (-want +got):\n%s", id, diff)
		}
	}
}

func TestOneWayMessagesAreAccepted(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "notification",
			body: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		},
		{
			name: "response to a server request",
			body: `{"jsonrpc":"2.0","id":"srv-1","result":{"ok":true}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.do(t, call{subject: "alice", session: session, body: tc.body})
			defer response.Body.Close()
			if response.StatusCode != http.StatusAccepted {
				t.Fatalf("expected 202, got %d", response.StatusCode)
			}
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if len(body) != 0 {
				t.Fatalf("expected an empty body, got %q", body)
			}
		})
	}
}

func TestMalformedMessagesAreRejected(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	for _, tc := range []struct {
		name     string
		body     string
		expected int
	}{
		{
			name:     "not json",
			body:     `{`,
			expected: http.StatusBadRequest,
		},
		{
			name:     "wrong jsonrpc version",
			body:     `{"jsonrpc":"1.0","id":2,"method":"tools/list"}`,
			expected: http.StatusBadRequest,
		},
		{
			// Batching was removed in MCP 2025-11-25.
			name:     "batch",
			body:     `[{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
			expected: http.StatusBadRequest,
		},
		{
			// A pretty-printed body is one message, not several: compaction
			// before framing is what keeps its newlines from smuggling a
			// second message onto the child's stdin.
			name:     "embedded newlines",
			body:     "{\"jsonrpc\":\"2.0\",\n\"id\":2,\"method\":\"tools/list\"}",
			expected: http.StatusOK,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.do(t, call{subject: "alice", session: session, body: tc.body})
			defer response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, response.StatusCode)
			}
		})
	}
}

func TestProtocolVersionHeader(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	for _, tc := range []struct {
		name     string
		protocol string
		expected int
	}{
		{
			name:     "absent assumes the pre-header revision",
			protocol: "",
			expected: http.StatusAccepted,
		},
		{
			name:     "current revision",
			protocol: "2025-11-25",
			expected: http.StatusAccepted,
		},
		{
			name:     "assumed revision",
			protocol: string(AssumedProtocolVersion),
			expected: http.StatusAccepted,
		},
		{
			name:     "unknown revision",
			protocol: "2099-01-01",
			expected: http.StatusBadRequest,
		},
		{
			name:     "garbage",
			protocol: "not-a-version",
			expected: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := h.do(t, call{
				subject:  "alice",
				session:  session,
				protocol: tc.protocol,
				body:     `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			})
			defer response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, response.StatusCode)
			}
		})
	}
}

func TestStandaloneGetIsRefused(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	response := h.do(t, call{method: http.MethodGet, subject: "alice", session: session})
	defer response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", response.StatusCode)
	}
	if allow := response.Header.Get("Allow"); allow == "" {
		t.Error("405 response carried no Allow header")
	}
}

func TestDeleteTerminatesSessionAndChild(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.StatusCode)
	}

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("DELETE did not end the child process")
	}

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "", 0)})
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after DELETE, got %d", after.StatusCode)
	}
}

func TestSessionCapIsPerIdentity(t *testing.T) {
	h := newHarness(t, Options{MaxSessions: 2})

	const attempts = 10
	var wg sync.WaitGroup
	statuses := make([]int, attempts)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := h.do(t, call{subject: "alice", body: initializeBody})
			defer response.Body.Close()
			statuses[i] = response.StatusCode
		}()
	}
	wg.Wait()

	var allowed, refused int
	for _, status := range statuses {
		switch status {
		case http.StatusOK:
			allowed++
		case http.StatusTooManyRequests:
			refused++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if allowed != 2 || refused != attempts-2 {
		t.Fatalf("expected the cap to hold at 2 under load, got %d allowed and %d refused", allowed, refused)
	}

	t.Run("another identity is not starved", func(t *testing.T) {
		response := h.do(t, call{subject: "bob", body: initializeBody})
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 for a second identity, got %d", response.StatusCode)
		}
	})

	t.Run("a released slot is reusable", func(t *testing.T) {
		h.transport.mu.Lock()
		var owned *session
		for _, s := range h.transport.sessions {
			if s.subject == "alice" {
				owned = s
				break
			}
		}
		h.transport.mu.Unlock()

		response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: owned.id})
		response.Body.Close()
		// The slot belongs to the child until it exits, which DELETE starts
		// rather than waits for.
		waitFor(t, "the terminated child to release its slot", func() bool {
			return h.transport.reservedSlots("alice") == 1
		})

		reopened := h.do(t, call{subject: "alice", body: initializeBody})
		defer reopened.Body.Close()
		if reopened.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 after freeing a slot, got %d", reopened.StatusCode)
		}
	})
}

func TestIdleSessionsAreReaped(t *testing.T) {
	h := newHarness(t, Options{IdleTimeout: 60 * time.Millisecond})
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("idle session's child was never reaped")
	}
	waitFor(t, "the reaped session to be unregistered", func() bool { return h.transport.sessionCount() == 0 })

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "", 0)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a reaped session, got %d", response.StatusCode)
	}
}

func TestActiveSessionSurvivesIdleSweep(t *testing.T) {
	h := newHarness(t, Options{IdleTimeout: 60 * time.Millisecond})
	session := h.initialize(t, "alice")

	// The exchange outlasts the idle timeout, and an in-flight request must
	// hold the session open.
	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, slowMethod, "held", 200*time.Millisecond)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a long request, got %d", response.StatusCode)
	}
}

func TestChildExitTearsDownSession(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, exitMethod, "", 0)})
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 when the child dies mid-request, got %d", response.StatusCode)
	}

	waitFor(t, "the dead session to be unregistered", func() bool { return h.transport.sessionCount() == 0 })

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "", 0)})
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after the child exited, got %d", after.StatusCode)
	}
}

func TestRequestTimeout(t *testing.T) {
	h := newHarness(t, Options{RequestTimeout: 50 * time.Millisecond})
	session := h.initialize(t, "alice")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, silentMethod, "", 0)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("expected 504, got %d", response.StatusCode)
	}
}

// TestConcurrentRequestsMayReuseACallerID covers the collision a session was
// once assumed to rule out. A client numbering its POSTs from a per-request
// counter sends two id 1s at once, which JSON-RPC forbids and which the Claude
// app was observed doing. Both must be served, each under its own id to the
// child and its own id back.
func TestConcurrentRequestsMayReuseACallerID(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	slow := make(chan map[string]any, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(1, observedIDMethod, "", 300*time.Millisecond)})
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			slow <- nil
			return
		}
		slow <- decodeMessage(t, response)
	}()

	waitFor(t, "the first request to reach the child", func() bool {
		return h.transport.pendingRequests() == 1
	})

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(1, observedIDMethod, "", 0)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the concurrent reuse of id 1, got %d", response.StatusCode)
	}
	second := decodeMessage(t, response)

	first := <-slow
	if first == nil {
		t.Fatal("the first request was refused")
	}

	for _, message := range []map[string]any{first, second} {
		if message["id"] != float64(1) {
			t.Errorf("expected the caller's own id 1 restored, got %v", message["id"])
		}
	}
	if observedID(t, first) == observedID(t, second) {
		t.Errorf("the child saw both requests under id %v", observedID(t, first))
	}
}

// TestRetryAfterCancelGetsItsOwnAnswer covers the collision no compliant
// client can avoid. A caller that hangs up mid-request leaves the child still
// working on that id, and the retry reuses it. Correlating on the caller's id
// would hand the retry the abandoned request's answer.
func TestRetryAfterCancelGetsItsOwnAnswer(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	abandoned, hangUp := context.WithCancel(t.Context())
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		response := h.do(t, call{ctx: abandoned, subject: "alice", session: session, body: requestBody(1, "tools/call", "abandoned", 300*time.Millisecond)})
		if response != nil {
			response.Body.Close()
		}
	}()

	waitFor(t, "the abandoned request to reach the child", func() bool {
		return h.transport.pendingRequests() == 1
	})
	hangUp()
	<-sent
	waitFor(t, "the abandoned request to leave the correlation map", func() bool {
		return h.transport.pendingRequests() == 0
	})

	// Outlasting the child's answer to the abandoned request is what puts the
	// retry in the way of it.
	response := h.do(t, call{subject: "alice", session: session, body: requestBody(1, "tools/call", "retry", time.Second)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for the retry, got %d", response.StatusCode)
	}

	result, _ := decodeMessage(t, response)["result"].(map[string]any)
	if result["echo"] != "retry" {
		t.Errorf("the retry was answered with %v, not its own result", result)
	}
}

func observedID(t *testing.T, message map[string]any) any {
	t.Helper()
	result, ok := message["result"].(map[string]any)
	if !ok {
		t.Fatalf("expected a result, got %v", message)
	}
	return result["observedId"]
}

// TestBadRequestNamesTheRefusal covers what a client is told when tailgate
// refuses its message. The status alone leaves a caller with a tool call that
// failed for no stated reason, and each of these sentinels names a mistake in
// the request the caller itself wrote.
func TestBadRequestNamesTheRefusal(t *testing.T) {
	h := newHarness(t, Options{})

	for _, tc := range []struct {
		name string
		err  error
	}{
		{name: "invalid message", err: errInvalidMessage},
		{name: "missing session id", err: errMissingSessionID},
		{name: "duplicate request id", err: errDuplicateRequestID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			h.transport.writeError(recorder, tc.err)

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", recorder.Code)
			}
			var refusal struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &refusal); err != nil {
				t.Fatalf("decode refusal: %v", err)
			}
			if refusal.Error.Message != tc.err.Error() {
				t.Errorf("expected the refusal named, got %q", refusal.Error.Message)
			}
		})
	}
}

// TestRefusalAboveBadRequestStaysOpaque holds the other half: a status outside
// the 400 family reports a failure of tailgate's own, whose detail names the
// child command and other internals an internet-facing response must not carry.
func TestRefusalAboveBadRequestStaysOpaque(t *testing.T) {
	h := newHarness(t, Options{})

	recorder := httptest.NewRecorder()
	h.transport.writeError(recorder, errUnauthenticated)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", recorder.Code)
	}
	if body := recorder.Body.String(); !strings.HasPrefix(body, http.StatusText(http.StatusInternalServerError)) {
		t.Errorf("expected the status text alone, got %q", body)
	}
}

func TestUnauthenticatedRequestNeverSpawns(t *testing.T) {
	for _, tc := range []struct {
		name string
		call call
	}{
		{
			name: "no identity in context",
			call: call{body: initializeBody},
		},
		{
			// A blank subject shares one cap bucket and one session namespace
			// across every caller that presents it, so it must be refused as
			// hard as an absent identity.
			name: "identity with a blank subject",
			call: call{blankIdentity: true, body: initializeBody},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Options{})

			response := h.do(t, tc.call)
			defer response.Body.Close()
			if response.StatusCode != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", response.StatusCode)
			}
			if count := h.transport.sessionCount(); count != 0 {
				t.Fatalf("expected no session to be spawned, got %d", count)
			}
			if slots := h.transport.reservedSlots(""); slots != 0 {
				t.Fatalf("an unauthenticated request reserved %d cap slots", slots)
			}
		})
	}
}

func TestRefusedRequestsAreAudited(t *testing.T) {
	h := newHarness(t, Options{Name: "docs", MaxSessions: 1})
	session := h.initialize(t, "alice")

	hijack := h.do(t, call{subject: "mallory", session: session, body: requestBody(2, "tools/list", "", 0)})
	hijack.Body.Close()
	if hijack.StatusCode != http.StatusNotFound {
		t.Fatalf("hijack: expected 404, got %d", hijack.StatusCode)
	}

	capped := h.do(t, call{subject: "alice", body: initializeBody})
	capped.Body.Close()
	if capped.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("cap: expected 429, got %d", capped.StatusCode)
	}

	blank := h.do(t, call{blankIdentity: true, body: initializeBody})
	blank.Body.Close()
	if blank.StatusCode != http.StatusInternalServerError {
		t.Fatalf("blank identity: expected 500, got %d", blank.StatusCode)
	}

	// The router binds sessions only for upstreams that mint their own, so
	// these records are the whole audit trail for a stdio upstream's refusals.
	want := []auditRecord{
		{Level: slog.LevelWarn.String(), Outcome: audit.OutcomeDeny, Subject: "mallory", Email: "mallory@example.com", Upstream: "docs", Reason: ReasonSessionBound},
		{Level: slog.LevelWarn.String(), Outcome: audit.OutcomeDeny, Subject: "alice", Email: "alice@example.com", Upstream: "docs", Reason: ReasonSessionCap},
		{Level: slog.LevelWarn.String(), Outcome: audit.OutcomeDeny, Upstream: "docs", Reason: ReasonUnauthorized},
	}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

func TestShutdownRefusesNewWorkAndDrains(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	inflight := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, slowMethod, "drain", 300*time.Millisecond)})
		defer response.Body.Close()
		inflight <- response.StatusCode
	}()
	waitFor(t, "the in-flight request to reach the child", func() bool {
		child.mu.Lock()
		defer child.mu.Unlock()
		return len(child.pending) == 1
	})

	// An already-expired context makes Shutdown mark the transport draining and
	// return immediately, so the 503 refusal is one deterministic request away.
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.transport.Shutdown(expired); err == nil {
		t.Fatal("expected the expired drain to report its deadline")
	}

	refused := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "", 0)})
	refused.Body.Close()
	if refused.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during drain, got %d", refused.StatusCode)
	}

	if status := <-inflight; status != http.StatusOK {
		t.Fatalf("the in-flight request should have completed, got %d", status)
	}
	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("shutdown left the child running")
	}
}

func TestCloseKillsStubbornChild(t *testing.T) {
	h := newHarness(t, Options{Env: []string{fakeChildLinger + "=1"}})
	h.transport.shutdownGrace = 50 * time.Millisecond
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	response.Body.Close()

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("a child that ignored its stdin close was never killed")
	}
	// A signal death, rather than any exit code, is what shows the child was
	// killed instead of leaving on its own.
	if code := child.cmd.ProcessState.ExitCode(); code != -1 {
		t.Fatalf("expected the child to die by signal, got exit code %d", code)
	}
}

func TestCloseReleasesBackgroundWork(t *testing.T) {
	baseline := runtime.NumGoroutine()

	transport := New(Options{
		Command: os.Args[0],
		Env:     []string{fakeChildEnv + "=1"},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.Identity{Subject: r.Header.Get(subjectHeader)}
		transport.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	}))
	h := &harness{transport: transport, gateway: gateway}
	h.initialize(t, "alice")
	h.initialize(t, "bob")

	gateway.Client().CloseIdleConnections()
	gateway.CloseClientConnections()
	gateway.Close()
	if err := transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if count := transport.sessionCount(); count != 0 {
		t.Fatalf("expected every session torn down, got %d", count)
	}

	waitFor(t, "goroutines to return to baseline", func() bool { return runtime.NumGoroutine() <= baseline })
}

func TestCloseIsIdempotentAfterShutdown(t *testing.T) {
	h := newHarness(t, Options{})
	h.initialize(t, "alice")

	if err := h.transport.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := h.transport.Close(); err != nil {
		t.Fatalf("close after shutdown: %v", err)
	}

	response := h.do(t, call{subject: "alice", body: initializeBody})
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after shutdown, got %d", response.StatusCode)
	}
}

// TestFailedInitializeReleasesItsCapSlot covers the leak direction of the cap.
// A reservation is taken before the spawn, so an upstream that fails every
// initialize would otherwise lock its caller out with 429 after MaxSessions
// attempts and stay that way until tailgate restarted, long after the command
// was fixed.
func TestFailedInitializeReleasesItsCapSlot(t *testing.T) {
	const maxSessions = 2

	for _, tc := range []struct {
		name     string
		options  Options
		expected int
	}{
		{
			name:     "child that cannot start",
			options:  Options{Command: "/nonexistent/tailgate-mcp-server"},
			expected: http.StatusBadGateway,
		},
		{
			name:     "child that exits before answering",
			options:  Options{Env: []string{fakeChildExitOnly + "=1"}},
			expected: http.StatusBadGateway,
		},
		{
			name:     "child that never answers initialize",
			options:  Options{Env: []string{fakeChildSilent + "=1"}, RequestTimeout: 50 * time.Millisecond},
			expected: http.StatusGatewayTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.options.MaxSessions = maxSessions
			h := newHarness(t, tc.options)
			h.transport.shutdownGrace = 50 * time.Millisecond

			for attempt := range maxSessions + 1 {
				response := h.do(t, call{subject: "alice", body: initializeBody})
				response.Body.Close()
				if response.StatusCode != tc.expected {
					t.Fatalf("attempt %d: expected %d, got %d", attempt, tc.expected, response.StatusCode)
				}
				// A slot outlives the request that failed, since it is the
				// child's until the child is reaped.
				waitFor(t, "the failed attempt to release its cap slot", func() bool {
					return h.transport.reservedSlots("alice") == 0
				})
			}
			if count := h.transport.sessionCount(); count != 0 {
				t.Errorf("expected no session for a child that never served one, got %d", count)
			}
		})
	}
}

// TestOversizedChildLineEndsTheSession defends the framing limit. A line past
// maxLineBytes leaves the stream unframed, so the reader stops. If the session
// outlived it, every later request would stall for the full request timeout
// instead of the 404 that makes a client re-initialize, and the caller's cap
// slot would never come back.
func TestOversizedChildLineEndsTheSession(t *testing.T) {
	h := newHarness(t, Options{})
	h.transport.shutdownGrace = 50 * time.Millisecond
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, floodMethod, "", 0)})
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for an unframeable response, got %d", response.StatusCode)
	}

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the wedged child was never ended")
	}
	waitFor(t, "the wedged session to be unregistered", func() bool { return h.transport.sessionCount() == 0 })
	if slots := h.transport.reservedSlots("alice"); slots != 0 {
		t.Errorf("the wedged session held %d cap slots", slots)
	}

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "", 0)})
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after the session ended, got %d", after.StatusCode)
	}
}

// TestWedgedStdinIsBounded defends the write to the child. A child that stays
// alive but stops reading its stdin fills the pipe buffer, and an unbounded
// write there wedges far more than the one request: the idle sweep skips a
// session with a request still active, so the session and its caller's cap slot
// are held for as long as the process lives.
func TestWedgedStdinIsBounded(t *testing.T) {
	// Comfortably past any pipe buffer, so the write cannot complete.
	oversized := strings.Repeat("x", 1<<20)

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "request",
			body: requestBody(3, "tools/call", oversized, 0),
		},
		{
			name: "notification",
			body: fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"echo":%q}}`, oversized),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Options{RequestTimeout: 200 * time.Millisecond})
			h.transport.shutdownGrace = 50 * time.Millisecond
			session := h.initialize(t, "alice")

			deaf := h.do(t, call{subject: "alice", session: session, body: requestBody(2, deafMethod, "", 0)})
			deaf.Body.Close()
			if deaf.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 from the child before it went deaf, got %d", deaf.StatusCode)
			}

			statuses := make(chan int, 1)
			go func() {
				response := h.do(t, call{subject: "alice", session: session, body: tc.body})
				defer response.Body.Close()
				statuses <- response.StatusCode
			}()

			select {
			case status := <-statuses:
				if status != http.StatusGatewayTimeout {
					t.Fatalf("expected 504 for a child that stopped reading stdin, got %d", status)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the write to a wedged child never returned")
			}

			waitFor(t, "the wedged session to be unregistered", func() bool { return h.transport.sessionCount() == 0 })
			waitFor(t, "the wedged session to release its cap slot", func() bool {
				return h.transport.reservedSlots("alice") == 0
			})

			after := h.do(t, call{subject: "alice", session: session, body: requestBody(4, "tools/list", "", 0)})
			after.Body.Close()
			if after.StatusCode != http.StatusNotFound {
				t.Fatalf("expected 404 after the wedged session ended, got %d", after.StatusCode)
			}
		})
	}
}

// TestCloseOutlivesAWedgedChild is the shutdown half of the same hazard: Close
// must not wait on a drain that only the child it has yet to kill can release.
func TestCloseOutlivesAWedgedChild(t *testing.T) {
	h := newHarness(t, Options{RequestTimeout: time.Hour})
	session := h.initialize(t, "alice")

	deaf := h.do(t, call{subject: "alice", session: session, body: requestBody(2, deafMethod, "", 0)})
	deaf.Body.Close()

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/call", strings.Repeat("x", 1<<20), 0)})
		response.Body.Close()
	}()
	waitFor(t, "the request to reach the wedged write", func() bool {
		child.mu.Lock()
		defer child.mu.Unlock()
		return len(child.pending) == 1
	})

	closed := make(chan error, 1)
	go func() { closed <- h.transport.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("close blocked on a request wedged against a child it had not killed")
	}
	<-blocked
}

// TestBodyLimits covers the two ways a POSTed message fails to arrive: too
// large, and never finished. The router pre-buffers bodies in the wired
// deployment, so these limits are what the transport holds when it is served
// directly, as any http.Handler can be.
func TestBodyLimits(t *testing.T) {
	t.Run("oversized body is too large", func(t *testing.T) {
		h := newHarness(t, Options{})

		body := strings.NewReader(requestBody(2, "tools/call", strings.Repeat("x", maxBodyBytes), 0))
		request := httptest.NewRequest(http.MethodPost, "/", body)
		request = request.WithContext(auth.WithIdentity(request.Context(), auth.Identity{Subject: "alice"}))
		recorder := httptest.NewRecorder()
		h.transport.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413, got %d", recorder.Code)
		}
	})

	t.Run("stalled body times out", func(t *testing.T) {
		h := newHarness(t, Options{RequestTimeout: 200 * time.Millisecond})

		conn, err := net.Dial("tcp", h.gateway.Listener.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		// Content-Length promises a body this client never finishes sending.
		request := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\n%s: alice\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"jsonrpc\":\"2.0\"", h.gateway.Listener.Addr(), subjectHeader)
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write request: %v", err)
		}

		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusRequestTimeout {
			t.Fatalf("expected 408 for a stalled body, got %d", response.StatusCode)
		}
	})
}

// TestCapSlotHoldsUntilTheChildExits pins the cap to live processes. Counting
// registrations instead lets a caller loop initialize and DELETE to hold
// children well past MaxSessions, since a terminated child has the full
// shutdown grace to exit and the loop can outrun it.
func TestCapSlotHoldsUntilTheChildExits(t *testing.T) {
	h := newHarness(t, Options{MaxSessions: 1, Env: []string{fakeChildLinger + "=1"}})
	h.transport.shutdownGrace = 500 * time.Millisecond
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	deleted := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", deleted.StatusCode)
	}

	// The child ignores its stdin close, so it is still running here.
	refused := h.do(t, call{subject: "alice", body: initializeBody})
	refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while the deleted child was still alive, got %d", refused.StatusCode)
	}

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the deleted child was never killed")
	}
	waitFor(t, "the exited child to release its slot", func() bool {
		return h.transport.reservedSlots("alice") == 0
	})

	reopened := h.do(t, call{subject: "alice", body: initializeBody})
	reopened.Body.Close()
	if reopened.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 once the child exited, got %d", reopened.StatusCode)
	}
}

// TestChildEnvironmentScrubsTailgateCredentials covers the child's view of
// tailgate's own secrets. A stdio upstream is third-party code running as
// tailgate, and TS_AUTHKEY in that environment would let it join nodes of its
// own to the tailnet.
func TestChildEnvironmentScrubsTailgateCredentials(t *testing.T) {
	const inherited = "TAILGATE_STDIO_TEST_INHERITED"
	t.Setenv(inherited, "visible")
	for _, name := range scrubbedEnv {
		t.Setenv(name, "tskey-auth-secret")
	}

	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	read := func(t *testing.T, name string) string {
		t.Helper()
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, envMethod, name, 0)})
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", response.StatusCode)
		}
		result, _ := decodeMessage(t, response)["result"].(map[string]any)
		value, _ := result["value"].(string)
		return value
	}

	for _, tc := range []struct {
		name     string
		variable string
		expected string
	}{
		{
			name:     "auth key",
			variable: "TS_AUTHKEY",
			expected: "",
		},
		{
			name:     "auth key alternate spelling",
			variable: "TS_AUTH_KEY",
			expected: "",
		},
		{
			// The scrub is a denylist: a child still needs the environment it
			// takes to run at all.
			name:     "ordinary variable",
			variable: inherited,
			expected: "visible",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if value := read(t, tc.variable); value != tc.expected {
				t.Fatalf("child saw %s=%q, expected %q", tc.variable, value, tc.expected)
			}
		})
	}
}

// TestChildEnvironmentPrefersTheUpstreamsOwnEntry covers what an upstream
// running under its own uid depends on. It cannot write tailgate's HOME, so it
// has to name its own, and the only place to name one is the upstream's Env.
// os/exec builds the child's environment keeping the last occurrence of each
// name, and Env is appended after the inherited environment, so it wins.
func TestChildEnvironmentPrefersTheUpstreamsOwnEntry(t *testing.T) {
	t.Setenv("HOME", "/inherited-from-tailgate")

	h := newHarness(t, Options{Env: []string{"HOME=/var/lib/tailgate-upstream"}})
	session := h.initialize(t, "alice")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, envMethod, "HOME", 0)})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	result, _ := decodeMessage(t, response)["result"].(map[string]any)
	if value, _ := result["value"].(string); value != "/var/lib/tailgate-upstream" {
		t.Fatalf("child saw HOME=%q, expected the upstream's own", value)
	}
}

// TestClaimedSessionSurvivesTheIdleSweep pins the resolve-and-claim to one
// critical section. A request that has resolved its session but not yet marked
// it busy used to be invisible to the reaper, which then terminated the child
// under it: the caller saw 502, and a client reads that as a broken upstream
// rather than the 404 that tells it to re-initialize.
func TestClaimedSessionSurvivesTheIdleSweep(t *testing.T) {
	h := newHarness(t, Options{IdleTimeout: time.Hour})
	session := h.initialize(t, "alice")
	future := time.Now().Add(2 * time.Hour)

	claimed, err := h.transport.sessionFor(t.Context(), session, auth.Identity{Subject: "alice"})
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}
	if taken := h.transport.takeIdleSessions(future); len(taken) != 0 {
		t.Fatalf("the sweep took %d sessions a request had already claimed", len(taken))
	}
	claimed.finish()

	taken := h.transport.takeIdleSessions(future)
	if len(taken) != 1 || taken[0] != claimed {
		t.Fatalf("expected the released session to be swept, got %v", taken)
	}
	taken[0].terminate()

	t.Run("a request that loses the race is a missing session", func(t *testing.T) {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "", 0)})
		defer response.Body.Close()
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("expected 404 for a swept session, got %d", response.StatusCode)
		}
	})
}

// TestRequestsRacingTheReaperAreNeverBadGateway runs traffic against an idle
// timeout short enough that the reaper is always a tick away.
func TestRequestsRacingTheReaperAreNeverBadGateway(t *testing.T) {
	h := newHarness(t, Options{IdleTimeout: time.Millisecond, MaxSessions: 8})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				response := h.do(t, call{subject: "alice", body: initializeBody})
				session := response.Header.Get(sessionHeader)
				status := response.StatusCode
				response.Body.Close()
				if status != http.StatusOK && status != http.StatusTooManyRequests {
					t.Errorf("initialize: expected 200 or 429, got %d", status)
					return
				}
				if status != http.StatusOK {
					continue
				}
				follow := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "", 0)})
				status = follow.StatusCode
				follow.Body.Close()
				if status != http.StatusOK && status != http.StatusNotFound {
					t.Errorf("a request racing the reaper got %d, expected 200 or 404", status)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestSessionLogTagsUpstreamOnce covers a duplicated log attribute. The caller
// tags the logger it hands each transport with the upstream that transport
// serves, so a transport tagging its own emitted "upstream" twice in every
// record it wrote.
func TestSessionLogTagsUpstreamOnce(t *testing.T) {
	logs := &syncBuffer{}
	h := newHarness(t, Options{
		Name:   "files",
		Logger: slog.New(slog.NewJSONHandler(logs, nil)).With("upstream", "files"),
	})
	h.initialize(t, "alice")

	written := strings.TrimSpace(logs.String())
	if written == "" {
		t.Fatal("expected the established session to be logged")
	}
	for _, line := range strings.Split(written, "\n") {
		if count := strings.Count(line, `"upstream"`); count != 1 {
			t.Errorf("expected 1 upstream attribute, got %d in %s", count, line)
		}
	}
}

// syncBuffer collects log output written from the transport's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A message carrying an id that correlates to nothing is none of the three
// shapes JSON-RPC defines. Passing one to the child would spend a caller-chosen
// id in the child's own id space on a message whose answer can never be routed
// back, so it is refused before any child sees it, under either era.
func TestMessagesOutsideTheJSONRPCShapesAreRejected(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "array id",
			body: `{"jsonrpc":"2.0","id":[1],"method":"tools/call","params":{}}`,
		},
		{
			name: "object id",
			body: `{"jsonrpc":"2.0","id":{"a":1},"method":"tools/call","params":{}}`,
		},
		{
			name: "null id with a method",
			body: `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{}}`,
		},
		{
			name: "neither a method nor a usable id",
			body: `{"jsonrpc":"2.0","id":null,"result":{}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bound := h.do(t, call{subject: "alice", session: session, body: tc.body})
			bound.Body.Close()
			if bound.StatusCode != http.StatusBadRequest {
				t.Errorf("session revision: expected 400, got %d", bound.StatusCode)
			}

			sessionless := h.do(t, call{subject: "alice", protocol: stateless, body: tc.body})
			defer sessionless.Body.Close()
			if sessionless.StatusCode != http.StatusBadRequest {
				t.Fatalf("stateless revision: expected 400, got %d", sessionless.StatusCode)
			}
			message := decodeMessage(t, sessionless)
			failure, _ := message["error"].(map[string]any)
			if code, ok := failure["code"].(float64); !ok || int(code) != protocol.CodeInvalidRequest {
				t.Errorf("expected code %d, got %v", protocol.CodeInvalidRequest, failure["code"])
			}
		})
	}
}

// Which copy of a repeated session header to resolve is not decidable, and this
// transport is what binds a session id to its caller. Reading the first would
// let a caller lead with a session it holds and trail with one it does not.
func TestRepeatedSessionHeaderIsRefused(t *testing.T) {
	h := newHarness(t, Options{})
	mine := h.initialize(t, "alice")
	theirs := h.initialize(t, "bob")

	for _, tc := range []struct {
		name   string
		method string
		body   string
	}{
		{
			name:   "post",
			method: http.MethodPost,
			body:   requestBody(2, "tools/list", "", 0),
		},
		{
			name:   "delete",
			method: http.MethodDelete,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body io.Reader
			if tc.body != "" {
				body = strings.NewReader(tc.body)
			}
			request, err := http.NewRequestWithContext(t.Context(), tc.method, h.gateway.URL, body)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Header.Set(subjectHeader, "alice")
			request.Header.Add(sessionHeader, mine)
			request.Header.Add(sessionHeader, theirs)

			response, err := h.gateway.Client().Do(request)
			if err != nil {
				t.Fatalf("%s: %v", tc.method, err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", response.StatusCode)
			}
		})
	}

	// The refusal must not have ended either session along the way.
	for subject, session := range map[string]string{"alice": mine, "bob": theirs} {
		response := h.do(t, call{subject: subject, session: session, body: requestBody(3, "tools/list", "", 0)})
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s lost its session to the refusal: got %d", subject, response.StatusCode)
		}
	}
}

// A child whose diagnostics run past what the reader can frame goes on writing
// them. Once the reader stops, the pipe fills and stops the child on its next
// write, which here is before it has read a single request.
func TestUnframeableStderrDoesNotStallTheChild(t *testing.T) {
	h := newHarness(t, Options{
		Env:            []string{fakeChildStderrFlood + "=1"},
		RequestTimeout: 10 * time.Second,
	})

	response := h.do(t, call{subject: "alice", body: initializeBody})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected the child to answer past its stderr flood, got %d", response.StatusCode)
	}
	if session := response.Header.Get(sessionHeader); session == "" {
		t.Error("initialize response carried no Mcp-Session-Id")
	}
}
