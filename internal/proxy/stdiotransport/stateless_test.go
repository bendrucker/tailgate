package stdiotransport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/audit"
	"github.com/bendrucker/tailgate/internal/protocol"
	"github.com/google/go-cmp/cmp"
)

const stateless = string(protocol.Rev20260728)

// statelessBody is a request as a stateless client sends it: no session, and
// its protocol version restated in the params _meta.
func statelessBody(id any, method string, params string) string {
	if params == "" {
		params = "{}"
	}
	meta := fmt.Sprintf(`"_meta":{"io.modelcontextprotocol/protocolVersion":%q}`, stateless)
	params = strings.TrimSuffix(params, "}")
	if params != "{" {
		params += ","
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":%q,"params":%s%s}}`, jsonID(id), method, params, meta)
}

func jsonID(id any) string {
	raw, err := json.Marshal(id)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func TestStatelessRequest(t *testing.T) {
	h := newHarness(t, Options{})

	response := h.do(t, call{subject: "alice", protocol: stateless, body: statelessBody(1, "tools/list", "")})
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if session := response.Header.Get(sessionHeader); session != "" {
		t.Errorf("stateless response minted a session id %q", session)
	}

	message := decodeMessage(t, response)
	if id, ok := message["id"].(float64); !ok || id != 1 {
		t.Errorf("expected the caller's own id back, got %v", message["id"])
	}
}

// A stateless client has no session to carry an id space, so nothing stops two
// concurrent requests from both calling themselves id 1. Each must still get
// its own answer.
func TestStatelessConcurrentRequestsReuseOneID(t *testing.T) {
	h := newHarness(t, Options{})

	const requests = 8
	var wait sync.WaitGroup
	echoes := make([]string, requests)
	for i := range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			echo := fmt.Sprintf("echo-%d", i)
			body := statelessBody(1, "tools/call", fmt.Sprintf(`{"echo":%q,"delay_ms":%d}`, echo, (requests-i)*5))
			response := h.do(t, call{subject: "alice", protocol: stateless, body: body})
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Errorf("request %d: expected 200, got %d", i, response.StatusCode)
				return
			}
			message := decodeMessage(t, response)
			if id, ok := message["id"].(float64); !ok || id != 1 {
				t.Errorf("request %d: expected id 1 back, got %v", i, message["id"])
			}
			result, _ := message["result"].(map[string]any)
			echoes[i], _ = result["echo"].(string)
		}()
	}
	wait.Wait()

	for i, echo := range echoes {
		if expected := fmt.Sprintf("echo-%d", i); echo != expected {
			t.Errorf("request %d took another request's answer: expected %q, got %q", i, expected, echo)
		}
	}
}

// One caller's requests share a child, and one caller's child is unreachable
// from another's.
func TestStatelessChildIsPerIdentity(t *testing.T) {
	h := newHarness(t, Options{})

	for _, subject := range []string{"alice", "alice", "bob"} {
		response := h.do(t, call{subject: subject, protocol: stateless, body: statelessBody(1, "tools/list", "")})
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", subject, response.StatusCode)
		}
	}

	h.transport.mu.Lock()
	defer h.transport.mu.Unlock()
	if len(h.transport.stateless) != 2 {
		t.Errorf("expected one child per identity, got %d", len(h.transport.stateless))
	}
	for _, subject := range []string{"alice", "bob"} {
		if _, ok := h.transport.stateless[subject]; !ok {
			t.Errorf("no child registered for %q", subject)
		}
	}
	if count := h.transport.perIdentity["alice"]; count != 1 {
		t.Errorf("alice's two requests cost %d children, expected 1", count)
	}
}

// A message carrying a correlation key and no method is neither request nor
// notification. Forwarding it verbatim would put a caller-chosen id into the
// namespace the transport mints from, where the child's answer to it satisfies
// another request's pending wait.
func TestStatelessRefusesAMessageWithNoMethod(t *testing.T) {
	h := newHarness(t, Options{})

	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":"tailgate-3","params":{%s},"result":{}}`,
		fmt.Sprintf(`%q:%q`, protocol.MetaProtocolVersion, stateless))
	response := h.do(t, call{subject: "alice", protocol: stateless, body: body})
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
}

// The binding follows the header rather than the declared revision. Naming the
// revision that dropped the header would otherwise shed the check, and this
// transport's own refusal is the only record of a stdio session probe.
func TestStatelessSessionBindingIsAudited(t *testing.T) {
	h := newHarness(t, Options{Name: "docs"})
	session := h.initialize(t, "alice")

	response := h.do(t, call{
		subject:  "mallory",
		protocol: stateless,
		session:  session,
		body:     statelessBody(1, "tools/list", ""),
	})
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for another identity's session, got %d", response.StatusCode)
	}
	want := []auditRecord{{
		Level:    slog.LevelWarn.String(),
		Outcome:  audit.OutcomeDeny,
		Subject:  "mallory",
		Email:    "mallory@example.com",
		Upstream: "docs",
		Reason:   ReasonSessionBound,
	}}
	if diff := cmp.Diff(want, h.audit.decisions()); diff != "" {
		t.Errorf("audit mismatch (-want +got):\n%s", diff)
	}
}

// A 400 whose body is not a recognized JSON-RPC error tells a client probing
// for the server's era that it predates the stateless revision, so a refusal in
// bare text talks the caller into a handshake this transport does not offer.
func TestStatelessRefusalsAreJSONRPC(t *testing.T) {
	h := newHarness(t, Options{})

	response := h.do(t, call{subject: "alice", protocol: stateless, body: `{"id":1,"method":"tools/list"}`})
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "application/json" {
		t.Fatalf("expected a JSON-RPC body, got %q", contentType)
	}
	message := decodeMessage(t, response)
	if version, _ := message["jsonrpc"].(string); version != "2.0" {
		t.Errorf("expected a JSON-RPC error, got %v", message)
	}
	failure, _ := message["error"].(map[string]any)
	if code, ok := failure["code"].(float64); !ok || int(code) != protocol.CodeInvalidRequest {
		t.Errorf("expected code %d, got %v", protocol.CodeInvalidRequest, failure["code"])
	}
}

// The stateless revision removed both the session header and the standalone
// GET stream, so the endpoint answers only POST.
func TestStatelessRefusesSessionMethods(t *testing.T) {
	for _, tc := range []struct {
		name     string
		method   string
		expected int
		allow    string
	}{
		{
			name:     "delete terminates nothing",
			method:   http.MethodDelete,
			expected: http.StatusMethodNotAllowed,
			allow:    "POST",
		},
		{
			name:     "get opens no standalone stream",
			method:   http.MethodGet,
			expected: http.StatusMethodNotAllowed,
			allow:    "POST",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Options{})
			response := h.do(t, call{subject: "alice", protocol: stateless, method: tc.method})
			defer response.Body.Close()
			if response.StatusCode != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, response.StatusCode)
			}
			if allow := response.Header.Get("Allow"); allow != tc.allow {
				t.Errorf("expected Allow %q, got %q", tc.allow, allow)
			}
		})
	}
}

// A revision tailgate does not speak is refused in the shape a modern client
// recognizes, so it retries rather than falling back to the legacy handshake.
func TestUnsupportedRevisionAnswersInJSONRPC(t *testing.T) {
	h := newHarness(t, Options{})

	response := h.do(t, call{subject: "alice", protocol: "2099-01-01", body: statelessBody(1, "tools/list", "")})
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.StatusCode)
	}

	var body struct {
		JSONRPC string `json:"jsonrpc"`
		Error   struct {
			Code int `json:"code"`
			Data struct {
				Supported []string `json:"supported"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.JSONRPC != "2.0" {
		t.Errorf("expected a JSON-RPC error response, got jsonrpc %q", body.JSONRPC)
	}
	if body.Error.Code != protocol.CodeUnsupportedProtocolVersion {
		t.Errorf("expected code %d, got %d", protocol.CodeUnsupportedProtocolVersion, body.Error.Code)
	}
	if len(body.Error.Data.Supported) != len(protocol.Supported) {
		t.Errorf("expected the supported revisions listed, got %v", body.Error.Data.Supported)
	}
}

// A child that predates the stateless revision still needs the handshake that
// revision removed, and tailgate runs it so the caller does not have to.
//
// The revision forbids keying that fallback to one error code, and the SDKs
// bear the reason out: a server with no notion of server/discover refuses it
// with whatever code its runtime uses. Only a code from the range the revision
// reserves for itself identifies a child that implements the method and
// declined anyway.
func TestStatelessHandshakeAcrossEras(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refusal string
		status  int
	}{
		{
			name:    "child that answers the probe is left alone",
			refusal: fakeChildDiscoverAnswers,
			status:  http.StatusOK,
		},
		{
			name:    "child that reports the method unknown gets initialize",
			refusal: strconv.Itoa(codeMethodNotFound),
			status:  http.StatusOK,
		},
		{
			name:    "child that reports invalid params gets initialize",
			refusal: strconv.Itoa(codeInvalidParams),
			status:  http.StatusOK,
		},
		{
			name:    "child that reports a code JSON-RPC does not define gets initialize",
			refusal: strconv.Itoa(codeUndefined),
			status:  http.StatusOK,
		},
		{
			name:    "child that refuses with a revision code is unavailable",
			refusal: strconv.Itoa(protocol.CodeUnsupportedProtocolVersion),
			status:  http.StatusBadGateway,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, Options{Env: []string{fakeChildDiscover + "=" + tc.refusal}})
			response := h.do(t, call{subject: "alice", protocol: stateless, body: statelessBody(1, "tools/list", "")})
			defer response.Body.Close()

			if response.StatusCode != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, response.StatusCode)
			}
			if tc.status != http.StatusOK {
				return
			}
			message := decodeMessage(t, response)
			result, _ := message["result"].(map[string]any)
			if method, _ := result["method"].(string); method != "tools/list" {
				t.Errorf("expected the caller's own request to reach the child, got %v", result)
			}
		})
	}
}

// The probe carries the caller's version and capabilities in _meta. A server
// that implements server/discover reads them, and answers a probe without them
// as though the method itself were unknown, which reads back as the legacy
// answer and misclassifies the era.
func TestStatelessProbeCarriesMeta(t *testing.T) {
	params := discoverParams()
	meta, ok := params["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("expected _meta on the probe, got %v", params)
	}
	if version := meta[protocol.MetaProtocolVersion]; version != string(protocol.Rev20260728) {
		t.Errorf("expected the probe to declare %q, got %v", protocol.Rev20260728, version)
	}
	if _, ok := meta[protocol.MetaClientCapabilities]; !ok {
		t.Errorf("expected the probe to declare client capabilities, got %v", meta)
	}
}

// subscriptions/listen is the one response held open, so it must escape the
// exchange timeout and carry the child's notifications as they arrive.
//
// The child acknowledges with a notification and answers the request only to
// end the subscription, so a transport that waited for that answer before
// writing any headers would hold every conforming child past the deadline and
// then refuse it. The timeout here is far shorter than the stream lives.
func TestStatelessSubscriptionStream(t *testing.T) {
	h := newHarness(t, Options{RequestTimeout: 500 * time.Millisecond})

	body := statelessBody("listen-1", listenMethod, `{"echo":"tick","notify":3}`)
	response := h.do(t, call{subject: "alice", protocol: stateless, body: body})
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "text/event-stream" {
		t.Fatalf("expected an SSE stream, got %q", contentType)
	}
	if buffering := response.Header.Get("X-Accel-Buffering"); buffering != "no" {
		t.Errorf("expected buffering disabled for intermediaries, got %q", buffering)
	}

	events := readEvents(t, response, 4)
	if method, _ := events[0]["method"].(string); method != "notifications/subscriptions/acknowledged" {
		t.Errorf("expected the acknowledgement first, got %v", events[0])
	}
	for i, event := range events[1:] {
		if method, _ := event["method"].(string); method != "notifications/message" {
			t.Fatalf("event %d is not a notification: %v", i+1, event)
		}
		params, _ := event["params"].(map[string]any)
		if seq, ok := params["seq"].(float64); !ok || int(seq) != i {
			t.Errorf("expected notification %d, got %v", i, params["seq"])
		}
	}
}

// The child answers the listen request to end the subscription, and that answer
// closes the stream carrying the caller's own id rather than the minted one it
// was correlated on.
func TestStatelessSubscriptionEnds(t *testing.T) {
	h := newHarness(t, Options{RequestTimeout: 500 * time.Millisecond})

	body := statelessBody("listen-1", listenMethod, `{"echo":"tick","notify":1,"end":true}`)
	response := h.do(t, call{subject: "alice", protocol: stateless, body: body})
	defer response.Body.Close()

	events := readEvents(t, response, 3)
	final := events[2]
	if id, _ := final["id"].(string); id != "listen-1" {
		t.Errorf("expected the final result to carry the caller's id, got %v", final["id"])
	}
	result, _ := final["result"].(map[string]any)
	if ended, _ := result["ended"].(bool); !ended {
		t.Errorf("expected the child's closing result, got %v", final)
	}
}

// readEvents reads count SSE data events off an open stream. A stream that
// stops short fails the test rather than hanging it: the response is held open
// by design, so nothing else would ever end the read.
func readEvents(t *testing.T, response *http.Response, count int) []map[string]any {
	t.Helper()
	type result struct {
		events []map[string]any
		err    error
	}
	done := make(chan result, 1)
	go func() {
		events, err := scanEvents(response, count)
		done <- result{events, err}
	}()
	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("read %d of %d events: %v", len(got.events), count, got.err)
		}
		return got.events
	case <-time.After(10 * time.Second):
		response.Body.Close()
		t.Fatalf("stream produced fewer than %d events", count)
		return nil
	}
}

func scanEvents(response *http.Response, count int) ([]map[string]any, error) {
	events := make([]map[string]any, 0, count)
	scanner := bufio.NewScanner(response.Body)
	var data strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data: "):
			data.WriteString(strings.TrimPrefix(line, "data: "))
		case line == "":
			if data.Len() == 0 {
				continue
			}
			var event map[string]any
			if err := json.Unmarshal([]byte(data.String()), &event); err != nil {
				return events, fmt.Errorf("decode event: %w", err)
			}
			events = append(events, event)
			data.Reset()
			if len(events) == count {
				return events, nil
			}
		}
	}
	return events, fmt.Errorf("stream ended: %w", scanner.Err())
}
