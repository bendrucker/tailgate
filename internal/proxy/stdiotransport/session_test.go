package stdiotransport

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newTestSession builds a session with no child, which is enough for the
// correlation and subscription bookkeeping that does not touch one.
func newTestSession() *session {
	return &session{
		id:        "test-session",
		subject:   "alice",
		logger:    testLogger(),
		exited:    make(chan struct{}),
		pending:   make(map[string]chan []byte),
		listeners: make(map[int64]*listener),
	}
}

// TestSubstituteMintsTheIDTheChildSees is the correctness argument the whole
// correlation scheme rests on: no id a caller writes reaches the child, so no
// two callers can name the same request and no caller can name one tailgate
// originated. The caller's own id comes back on the answer, since that is the
// only id the caller will recognize.
func TestSubstituteMintsTheIDTheChildSees(t *testing.T) {
	for _, tc := range []struct {
		name string
		line string
	}{
		{
			name: "a numeric caller id",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"echo":"a"}}`,
		},
		{
			name: "a string caller id",
			line: `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"echo":"a"}}`,
		},
		{
			// A caller that has read a minted id off the wire and writes its own
			// request under it still gets an id of tailgate's choosing.
			name: "a caller id shaped like a minted one",
			line: `{"jsonrpc":"2.0","id":"tailgate-1","method":"tools/call","params":{"echo":"a"}}`,
		},
		{
			// An id past what a float64 holds exactly, which a round trip
			// through a decoded number would round away.
			name: "an id larger than a float64",
			line: `{"jsonrpc":"2.0","id":9007199254740993,"method":"tools/call","params":{"echo":"a"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller, err := parseMessage([]byte(tc.line))
			if err != nil {
				t.Fatalf("parse the caller's message: %v", err)
			}

			s := newTestSession()
			rewritten, key, err := s.substitute(caller.Line)
			if err != nil {
				t.Fatalf("substitute: %v", err)
			}
			sent, err := parseMessage(rewritten)
			if err != nil {
				t.Fatalf("parse what the child would read: %v", err)
			}

			if string(sent.ID) != `"tailgate-1"` {
				t.Errorf("the child saw id %s, want the minted one", sent.ID)
			}
			if key != sent.Key {
				t.Errorf("the reported key %q does not correlate the message's own id %s", key, sent.ID)
			}
			if sent.Method != caller.Method {
				t.Errorf("method = %q, want %q", sent.Method, caller.Method)
			}
			if echo := echoParam(sent); echo != "a" {
				t.Errorf("the caller's params did not survive the rewrite: %s", sent.Line)
			}

			answer := fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, sent.ID)
			restored, err := setID(answer, caller.ID)
			if err != nil {
				t.Fatalf("restore the caller's id: %v", err)
			}
			answered, err := parseMessage(restored)
			if err != nil {
				t.Fatalf("parse the restored answer: %v", err)
			}
			if string(answered.ID) != string(caller.ID) {
				t.Errorf("the caller was answered under id %s, want its own %s", answered.ID, caller.ID)
			}
		})
	}
}

// TestMintedIDsAreUnique holds the other half. Concurrent requests on one
// session mint at the same time, and two that collided would leave one of them
// waiting on a correlation key the other had already claimed.
func TestMintedIDsAreUnique(t *testing.T) {
	const minters, each = 8, 128
	s := newTestSession()

	keys := make(chan string, minters*each)
	var wait sync.WaitGroup
	for range minters {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range each {
				id, key := s.mintID()
				if key != correlationKey(id) {
					t.Errorf("key %q does not correlate id %s", key, id)
				}
				keys <- key
			}
		}()
	}
	wait.Wait()
	close(keys)

	seen := make(map[string]bool, minters*each)
	for key := range keys {
		if seen[key] {
			t.Fatalf("%q was minted twice", key)
		}
		seen[key] = true
	}
	if len(seen) != minters*each {
		t.Errorf("minted %d distinct ids, want %d", len(seen), minters*each)
	}
}

// TestSubstituteRefusesWhatIsNotAMessage covers the rewrite failing rather than
// sending the caller's own id on because it could not be replaced.
func TestSubstituteRefusesWhatIsNotAMessage(t *testing.T) {
	s := newTestSession()
	if _, _, err := s.substitute([]byte(`["not","an","object"]`)); err != errInvalidMessage {
		t.Fatalf("substitute = %v, want %v", err, errInvalidMessage)
	}
}

// TestDrainNotifications covers the ordering a subscription ends on. The
// child's closing result and its notifications arrive on separate channels, so
// what it already emitted goes out first.
func TestDrainNotifications(t *testing.T) {
	for _, tc := range []struct {
		name     string
		queued   []string
		closed   bool
		expected []string
		open     bool
	}{
		{
			name:     "what the stream already holds goes out in order",
			queued:   []string{`{"seq":0}`, `{"seq":1}`, `{"seq":2}`},
			expected: []string{`{"seq":0}`, `{"seq":1}`, `{"seq":2}`},
			open:     true,
		},
		{
			name: "a stream holding nothing may still carry more",
			open: true,
		},
		{
			name:     "a stream the child has ended carries what it held and no more",
			queued:   []string{`{"seq":0}`},
			closed:   true,
			expected: []string{`{"seq":0}`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := &listener{notifications: make(chan []byte, notificationBuffer)}
			for _, notification := range tc.queued {
				l.notifications <- []byte(notification)
			}
			if tc.closed {
				close(l.notifications)
			}

			recorder := httptest.NewRecorder()
			open := drainNotifications(newEventStream(recorder), l)

			if open != tc.open {
				t.Errorf("drainNotifications = %v, want %v", open, tc.open)
			}
			var expected strings.Builder
			for _, notification := range tc.expected {
				fmt.Fprintf(&expected, "data: %s\n\n", notification)
			}
			if recorder.Body.String() != expected.String() {
				t.Errorf("stream wrote %q, want %q", recorder.Body.String(), expected.String())
			}
		})
	}
}

// TestDeliverRoutesByCorrelationKey covers the reader's fan-out, including the
// two messages it must not treat as answers: a notification, which belongs to
// the subscription streams, and a request the child originated, which has no
// HTTP response to ride on.
func TestDeliverRoutesByCorrelationKey(t *testing.T) {
	s := newTestSession()
	l, _, err := s.listen(4)
	if err != nil {
		t.Fatalf("open a subscription stream: %v", err)
	}

	minted, key := s.mintID()
	waiter := make(chan []byte, 1)
	s.pending[key] = waiter

	s.deliver([]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{}}`))
	s.deliver([]byte(`{"jsonrpc":"2.0","id":"server-1","method":"sampling/createMessage"}`))
	s.deliver([]byte(`{"jsonrpc":"2.0","id":"nobody-waiting","result":{}}`))
	s.deliver(fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, minted))

	select {
	case answer := <-waiter:
		var envelope struct {
			Result struct {
				OK bool `json:"ok"`
			} `json:"result"`
		}
		if err := json.Unmarshal(answer, &envelope); err != nil {
			t.Fatalf("decode the answer: %v", err)
		}
		if !envelope.Result.OK {
			t.Errorf("the waiter got %s", answer)
		}
	default:
		t.Fatal("the waiting request was never answered")
	}
	if len(s.pending) != 0 {
		t.Errorf("the answered request stayed in the correlation map")
	}
	if count := len(l.notifications); count != 1 {
		t.Errorf("the subscription stream carried %d messages, want the notification alone", count)
	}
}
