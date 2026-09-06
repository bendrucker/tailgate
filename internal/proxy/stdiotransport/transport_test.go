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

// testDeadline bounds a wait that only expires when the code under test is
// broken, so a hung expectation fails the test rather than the package.
const testDeadline = 10 * time.Second

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
	// children hands out the children this upstream spawns, so a test can
	// drive the one a particular request started.
	children *childScript
}

// newHarness serves an upstream whose children answer as a minimal MCP server
// does.
func newHarness(t *testing.T, options Options) *harness {
	t.Helper()
	return newScriptedHarness(t, options, echoServer)
}

func newScriptedHarness(t *testing.T, options Options, answer func(*scriptedChild, message)) *harness {
	t.Helper()
	children := newChildScript(answer)
	if options.StartChild == nil {
		options.StartChild = children.start
	}
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
	return &harness{transport: transport, gateway: gateway, audit: decisions, children: children}
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
	// abandoned before its answer, and do reports that as a nil response.
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

func (h *harness) session(t *testing.T, id string) *session {
	t.Helper()
	h.transport.mu.Lock()
	defer h.transport.mu.Unlock()
	s, ok := h.transport.sessions[id]
	if !ok {
		t.Fatalf("no session is registered under %q", id)
	}
	return s
}

func requestBody(id int, method, echo string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":%q,"params":{"echo":%q}}`, id, method, echo)
}

func decodeMessage(t *testing.T, response *http.Response) map[string]any {
	t.Helper()
	var message map[string]any
	if err := json.NewDecoder(response.Body).Decode(&message); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return message
}

func awaitClose(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(testDeadline):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// waitFor polls for state the transport publishes no signal for, which is the
// tail of a teardown: the unregistration and cap release that follow a child's
// exit on the supervising goroutine.
func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
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

// pendingRequests reports the correlation keys registered across every live
// session, which is how a test sees an abandoned request leave the correlation
// map.
func (t *Transport) pendingRequests() int {
	t.mu.Lock()
	sessions := slices.Collect(maps.Values(t.sessions))
	t.mu.Unlock()

	count := 0
	for _, s := range sessions {
		s.mu.Lock()
		count += len(s.pending)
		s.mu.Unlock()
	}
	return count
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

	if bound := h.session(t, session); bound.subject != "alice" {
		t.Fatalf("session was registered against %q, not the initializing identity", bound.subject)
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
			response := h.do(t, call{subject: tc.subject, session: session, body: requestBody(2, "tools/list", "")})
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
			call:     call{subject: "alice", body: requestBody(2, "tools/list", "")},
			expected: http.StatusBadRequest,
		},
		{
			name:     "unknown session",
			call:     call{subject: "alice", session: "not-a-session", body: requestBody(2, "tools/list", "")},
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

// TestConcurrentRequestsCorrelateByID answers every in-flight request in the
// reverse of the order the child received them, so a transport that paired
// answers by arrival would mismatch all but the middle one.
func TestConcurrentRequestsCorrelateByID(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	const requests = 24
	var wg sync.WaitGroup
	results := make([]map[string]any, requests)
	for i := range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := i + 100
			response := h.do(t, call{
				subject: "alice",
				session: session,
				body:    requestBody(id, "tools/call", fmt.Sprintf("echo-%d", id)),
			})
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", id, response.StatusCode)
				return
			}
			results[i] = decodeMessage(t, response)
		}()
	}

	inflight := make([]message, 0, requests)
	for range requests {
		inflight = append(inflight, held.next(t))
	}
	slices.Reverse(inflight)
	for _, msg := range inflight {
		child.result(msg, fmt.Sprintf(`{"method":%q,"echo":%q}`, msg.Method, echoParam(msg)))
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

// TestPostedResponseNeverReachesTheChild covers the one caller message that
// could otherwise carry an id of the caller's choosing into the namespace
// requests are minted from. The stateful revisions let a client POST a
// response, so tailgate must answer one with 202, but deliver drops the
// server-initiated direction that would have asked for it.
//
// The attack it defends against: name the minted id a live request is waiting
// on, and a child that reflects the response back answers that request's waiter
// with the caller's own payload. The id the exploit body names is taken from
// the request the child is holding, so it is the live one whatever the minting
// format is.
func TestPostedResponseNeverReachesTheChild(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	answered := make(chan map[string]any, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(9, "tools/call", "mine")})
		defer response.Body.Close()
		answered <- decodeMessage(t, response)
	}()
	inflight := held.next(t)

	posted := h.do(t, call{
		subject: "alice",
		session: session,
		body:    fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"stolen":true}}`, inflight.ID),
	})
	posted.Body.Close()
	if posted.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202 for a POSTed response, got %d", posted.StatusCode)
	}

	child.result(inflight, `{"echo":"mine"}`)
	result, _ := (<-answered)["result"].(map[string]any)
	if result["echo"] != "mine" {
		t.Errorf("the in-flight request was answered with %v", result)
	}

	for _, sent := range child.messagesSent() {
		if sent.IsResponse() {
			t.Errorf("a POSTed response reached the child: %s", sent.Line)
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
	child := h.children.next(t)

	response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", response.StatusCode)
	}
	awaitClose(t, child.exited, "DELETE to end the child")

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "")})
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
	sessions := make([]string, attempts)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := h.do(t, call{subject: "alice", body: initializeBody})
			defer response.Body.Close()
			statuses[i] = response.StatusCode
			sessions[i] = response.Header.Get(sessionHeader)
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
		id := sessions[slices.Index(statuses, http.StatusOK)]
		owned := h.session(t, id)

		response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: id})
		response.Body.Close()
		// The slot belongs to the child until it exits, which DELETE starts
		// rather than waits for, and the session is announced as exited only
		// once its slot is back.
		awaitClose(t, owned.exited, "the terminated child to release its slot")
		if slots := h.transport.reservedSlots("alice"); slots != 1 {
			t.Fatalf("expected one slot left held, got %d", slots)
		}

		reopened := h.do(t, call{subject: "alice", body: initializeBody})
		defer reopened.Body.Close()
		if reopened.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 after freeing a slot, got %d", reopened.StatusCode)
		}
	})
}

// TestIdleSessionsAreReaped covers the background sweep end to end. The reaper
// unregisters a session before terminating its child, so a child that has
// exited is a session no later request can reach.
func TestIdleSessionsAreReaped(t *testing.T) {
	h := newHarness(t, Options{IdleTimeout: 60 * time.Millisecond})
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	awaitClose(t, child.exited, "the idle session's child to be reaped")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "")})
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for a reaped session, got %d", response.StatusCode)
	}
}

// TestActiveSessionSurvivesIdleSweep holds a request open across a sweep that
// would otherwise take the session, and drives the sweep directly so the
// test controls the ordering.
func TestActiveSessionSurvivesIdleSweep(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{IdleTimeout: time.Hour}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	answered := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "held")})
		defer response.Body.Close()
		answered <- response.StatusCode
	}()
	inflight := held.next(t)

	if taken := h.transport.takeIdleSessions(time.Now().Add(2 * time.Hour)); len(taken) != 0 {
		t.Fatalf("the sweep took %d sessions with a request in flight", len(taken))
	}

	child.result(inflight, `{"echo":"held"}`)
	if status := <-answered; status != http.StatusOK {
		t.Fatalf("expected 200 for a request held across the sweep, got %d", status)
	}
}

func TestChildExitTearsDownSession(t *testing.T) {
	h := newScriptedHarness(t, Options{}, func(c *scriptedChild, msg message) {
		if msg.Method == "tools/call" {
			c.Kill()
			return
		}
		echoServer(c, msg)
	})
	session := h.initialize(t, "alice")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "")})
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 when the child dies mid-request, got %d", response.StatusCode)
	}

	waitFor(t, "the dead session to be unregistered", func() bool { return h.transport.sessionCount() == 0 })

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "")})
	after.Body.Close()
	if after.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 after the child exited, got %d", after.StatusCode)
	}
}

func TestRequestTimeout(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{RequestTimeout: 50 * time.Millisecond}, held.answer)
	session := h.initialize(t, "alice")

	response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "")})
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
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	answers := make(chan map[string]any, 2)
	for _, echo := range []string{"first", "second"} {
		go func() {
			response := h.do(t, call{subject: "alice", session: session, body: requestBody(1, "tools/call", echo)})
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				answers <- nil
				return
			}
			answers <- decodeMessage(t, response)
		}()
	}

	first, second := held.next(t), held.next(t)
	if first.Key == second.Key {
		t.Fatalf("the child saw both requests under id %s", first.ID)
	}
	child.result(second, fmt.Sprintf(`{"echo":%q}`, echoParam(second)))
	child.result(first, fmt.Sprintf(`{"echo":%q}`, echoParam(first)))

	echoes := map[string]bool{}
	for range 2 {
		message := <-answers
		if message == nil {
			t.Fatal("a request reusing id 1 was refused")
		}
		if message["id"] != float64(1) {
			t.Errorf("expected the caller's own id 1 restored, got %v", message["id"])
		}
		result, _ := message["result"].(map[string]any)
		echo, _ := result["echo"].(string)
		echoes[echo] = true
	}
	if !echoes["first"] || !echoes["second"] {
		t.Errorf("each request must get its own answer, got %v", echoes)
	}
}

// TestRetryAfterCancelGetsItsOwnAnswer covers the collision no compliant
// client can avoid. A caller that hangs up mid-request leaves the child still
// working on that id, and the retry reuses it. Correlating on the caller's id
// would hand the retry the abandoned request's answer, which the child here
// delivers first.
func TestRetryAfterCancelGetsItsOwnAnswer(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)

	abandoned, hangUp := context.WithCancel(t.Context())
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		response := h.do(t, call{ctx: abandoned, subject: "alice", session: session, body: requestBody(1, "tools/call", "abandoned")})
		if response != nil {
			response.Body.Close()
		}
	}()
	first := held.next(t)
	hangUp()
	<-sent
	// The child is still working on the abandoned request, but nothing is
	// waiting for its answer any more, and a correlation entry left behind
	// would leak one per request a caller gives up on.
	waitFor(t, "the abandoned request to leave the correlation map", func() bool {
		return h.transport.pendingRequests() == 0
	})

	answered := make(chan map[string]any, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(1, "tools/call", "retry")})
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			answered <- nil
			return
		}
		answered <- decodeMessage(t, response)
	}()
	retry := held.next(t)

	child.result(first, `{"echo":"abandoned"}`)
	child.result(retry, `{"echo":"retry"}`)

	message := <-answered
	if message == nil {
		t.Fatal("the retry was refused")
	}
	result, _ := message["result"].(map[string]any)
	if result["echo"] != "retry" {
		t.Errorf("the retry was answered with %v, not its own result", result)
	}
}

// TestBadRequestNamesTheRefusal covers what a client is told when tailgate
// refuses its message. The status alone leaves a caller with a tool call that
// failed for no stated reason, and each of these sentinels names a mistake in
// the request the caller itself wrote. What the caller is told is the
// transport's own text: a sentinel's is written for the log, where the package
// name that prefixes it belongs, and an internet-facing response is no place
// to disclose it.
func TestBadRequestNamesTheRefusal(t *testing.T) {
	h := newHarness(t, Options{})

	for sentinel, message := range badRequestMessages {
		if strings.Contains(message, "stdiotransport") {
			t.Errorf("the text answering %v carries the package name: %q", sentinel, message)
		}
	}

	for _, tc := range []struct {
		name     string
		err      error
		expected string
	}{
		{name: "invalid message", err: errInvalidMessage, expected: "invalid JSON-RPC message"},
		{name: "missing session id", err: errMissingSessionID, expected: "Mcp-Session-Id is required"},
		{name: "duplicate request id", err: errDuplicateRequestID, expected: "duplicate in-flight JSON-RPC id"},
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
			if refusal.Error.Message != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, refusal.Error.Message)
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
			if started := h.children.startedCount(); started != 0 {
				t.Fatalf("expected no child to be started, got %d", started)
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

	hijack := h.do(t, call{subject: "mallory", session: session, body: requestBody(2, "tools/list", "")})
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

// TestShutdownRefusesNewWorkAndDrains covers the drain around an exchange
// already with the child. The child here keeps working after its stdin closes,
// which is what a well-behaved server does with the request it has in hand.
func TestShutdownRefusesNewWorkAndDrains(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)
	child.linger.Store(true)

	inflight := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "drain")})
		defer response.Body.Close()
		inflight <- response.StatusCode
	}()
	pending := held.next(t)

	// An already-expired context makes Shutdown mark the transport draining and
	// return immediately, so the 503 refusal is one deterministic request away.
	expired, cancel := context.WithCancel(t.Context())
	cancel()
	if err := h.transport.Shutdown(expired); err == nil {
		t.Fatal("expected the expired drain to report its deadline")
	}

	refused := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "")})
	refused.Body.Close()
	if refused.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 during drain, got %d", refused.StatusCode)
	}

	child.result(pending, `{"echo":"drain"}`)
	if status := <-inflight; status != http.StatusOK {
		t.Fatalf("the in-flight request should have completed, got %d", status)
	}
}

// TestShutdownEndsEveryChild: a child that exits when its stdin closes is gone by the time Shutdown returns.
func TestShutdownEndsEveryChild(t *testing.T) {
	h := newHarness(t, Options{})
	h.initialize(t, "alice")
	child := h.children.next(t)

	if err := h.transport.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	awaitClose(t, child.exited, "shutdown to end the child")
}

// TestCloseKillsALingeringChild covers the child that ignores its stdin
// closing. Close skips the grace period termination allows, so it neither waits
// for such a child nor leaves it running.
func TestCloseKillsALingeringChild(t *testing.T) {
	h := newHarness(t, Options{})
	h.initialize(t, "alice")
	child := h.children.next(t)
	child.linger.Store(true)

	if err := h.transport.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	awaitClose(t, child.exited, "close to kill the child")
	if err := child.Wait(); err != errChildKilled {
		t.Errorf("expected the child to be killed, got %v", err)
	}
}

func TestCloseReleasesBackgroundWork(t *testing.T) {
	baseline := runtime.NumGoroutine()

	children := newChildScript(echoServer)
	transport := New(Options{
		StartChild: children.start,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.Identity{Subject: r.Header.Get(subjectHeader)}
		transport.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), identity)))
	}))
	h := &harness{transport: transport, gateway: gateway, children: children}
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
		answer   func(*scriptedChild, message)
		startErr error
		expected int
	}{
		{
			name:     "child that cannot start",
			startErr: fmt.Errorf("no such command"),
			expected: http.StatusBadGateway,
		},
		{
			name:     "child that exits before answering",
			answer:   func(c *scriptedChild, msg message) { c.Kill() },
			expected: http.StatusBadGateway,
		},
		{
			name:     "child that never answers initialize",
			options:  Options{RequestTimeout: 50 * time.Millisecond},
			answer:   func(*scriptedChild, message) {},
			expected: http.StatusGatewayTimeout,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := tc.answer
			if answer == nil {
				answer = echoServer
			}
			options := tc.options
			options.MaxSessions = maxSessions
			h := newScriptedHarness(t, options, answer)
			h.children.startErr = tc.startErr

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

// TestUnframeableOutputEndsTheSession defends the framing limit. Output that
// cannot be split into messages leaves the reader with nothing it can trust, so
// the session ends. If it outlived that, every later request would stall for
// the full request timeout instead of the 404 that makes a client
// re-initialize, and the caller's cap slot would never come back.
func TestUnframeableOutputEndsTheSession(t *testing.T) {
	held := holding("tools/call")
	h := newScriptedHarness(t, Options{}, held.answer)
	session := h.initialize(t, "alice")
	child := h.children.next(t)
	s := h.session(t, session)

	answered := make(chan int, 1)
	go func() {
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/call", "")})
		defer response.Body.Close()
		answered <- response.StatusCode
	}()
	held.next(t)
	child.endOutput(bufio.ErrTooLong)

	if status := <-answered; status != http.StatusBadGateway {
		t.Fatalf("expected 502 for an unframeable response, got %d", status)
	}
	awaitClose(t, s.exited, "the wedged child to be reaped")
	if slots := h.transport.reservedSlots("alice"); slots != 0 {
		t.Errorf("the wedged session held %d cap slots", slots)
	}

	after := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/list", "")})
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
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "request",
			body: requestBody(3, "tools/call", ""),
		},
		{
			name: "notification",
			body: `{"jsonrpc":"2.0","method":"notifications/progress"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Options{RequestTimeout: 200 * time.Millisecond})
			session := h.initialize(t, "alice")
			child := h.children.next(t)
			s := h.session(t, session)
			child.deaf.Store(true)

			response := h.do(t, call{subject: "alice", session: session, body: tc.body})
			response.Body.Close()
			if response.StatusCode != http.StatusGatewayTimeout {
				t.Fatalf("expected 504 for a child that stopped reading stdin, got %d", response.StatusCode)
			}

			awaitClose(t, s.exited, "the wedged session to release its cap slot")
			if slots := h.transport.reservedSlots("alice"); slots != 0 {
				t.Errorf("the wedged session held %d cap slots", slots)
			}

			after := h.do(t, call{subject: "alice", session: session, body: requestBody(4, "tools/list", "")})
			after.Body.Close()
			if after.StatusCode != http.StatusNotFound {
				t.Fatalf("expected 404 after the wedged session ended, got %d", after.StatusCode)
			}
		})
	}
}

// TestCloseOutlivesAWedgedChild is the shutdown half of the same hazard: Close
// must not wait on a drain that only the child it has yet to kill can release.
// The write below is bounded by an hour, so nothing but the kill releases it.
func TestCloseOutlivesAWedgedChild(t *testing.T) {
	h := newHarness(t, Options{RequestTimeout: time.Hour})
	session := h.initialize(t, "alice")
	child := h.children.next(t)
	child.deaf.Store(true)

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(3, "tools/call", "")})
		response.Body.Close()
	}()

	closed := make(chan error, 1)
	go func() { closed <- h.transport.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(testDeadline):
		t.Fatal("close blocked on a request wedged against a child it had not killed")
	}
	awaitClose(t, blocked, "the wedged request to be released")
}

// TestBodyLimits covers the two ways a POSTed message fails to arrive: too
// large, and never finished. The router pre-buffers bodies in the wired
// deployment, so these limits are what the transport holds when it is served
// directly, as any http.Handler can be.
func TestBodyLimits(t *testing.T) {
	t.Run("oversized body is too large", func(t *testing.T) {
		h := newHarness(t, Options{})

		body := strings.NewReader(requestBody(2, "tools/call", strings.Repeat("x", maxBodyBytes)))
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

		if err := conn.SetReadDeadline(time.Now().Add(testDeadline)); err != nil {
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
	h := newHarness(t, Options{MaxSessions: 1})
	session := h.initialize(t, "alice")
	child := h.children.next(t)
	s := h.session(t, session)
	// A child that ignores its stdin closing is one the grace period is still
	// running for, which is where a second initialize must still be refused.
	child.linger.Store(true)

	deleted := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	deleted.Body.Close()
	if deleted.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", deleted.StatusCode)
	}

	refused := h.do(t, call{subject: "alice", body: initializeBody})
	refused.Body.Close()
	if refused.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while the deleted child was still alive, got %d", refused.StatusCode)
	}

	child.Kill()
	awaitClose(t, s.exited, "the exited child to release its slot")

	reopened := h.do(t, call{subject: "alice", body: initializeBody})
	reopened.Body.Close()
	if reopened.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 once the child exited, got %d", reopened.StatusCode)
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
		response := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "")})
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
				follow := h.do(t, call{subject: "alice", session: session, body: requestBody(2, "tools/list", "")})
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
		{
			name: "neither a method nor an id at all",
			body: `{"jsonrpc":"2.0","params":{}}`,
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
			body:   requestBody(2, "tools/list", ""),
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
		response := h.do(t, call{subject: subject, session: session, body: requestBody(3, "tools/list", "")})
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Errorf("%s lost its session to the refusal: got %d", subject, response.StatusCode)
		}
	}
}
