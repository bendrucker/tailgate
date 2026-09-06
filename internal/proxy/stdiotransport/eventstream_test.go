package stdiotransport

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewEventStreamCommitsItsHeaders covers what a client sees before the
// first event. Committing the headers is what makes the stream visible, and the
// buffering hint is what keeps a reverse proxy from holding notifications back
// until the subscription ends.
func TestNewEventStreamCommitsItsHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	newEventStream(recorder)

	if recorder.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recorder.Code)
	}
	for name, expected := range map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"X-Accel-Buffering": "no",
	} {
		if value := recorder.Header().Get(name); value != expected {
			t.Errorf("%s = %q, want %q", name, value, expected)
		}
	}
}

// TestEventStreamSend covers the framing. SSE ends an event at a blank line and
// starts a new one at each unprefixed line, so a message carrying a newline
// would arrive as several events, each of them unparseable. The child's output
// is newline-delimited only by convention on the way in, and a message it wrote
// with a CRLF ending would otherwise carry the carriage return into the event.
func TestEventStreamSend(t *testing.T) {
	for _, tc := range []struct {
		name     string
		message  string
		expected string
	}{
		{
			name:     "one message is one event",
			message:  `{"jsonrpc":"2.0","id":1}`,
			expected: "data: {\"jsonrpc\":\"2.0\",\"id\":1}\n\n",
		},
		{
			name:     "a message spanning lines is still one event",
			message:  "{\n\"jsonrpc\":\"2.0\"\n}",
			expected: "data: {\ndata: \"jsonrpc\":\"2.0\"\ndata: }\n\n",
		},
		{
			name:     "a trailing newline does not open a second event",
			message:  "{\"id\":1}\n",
			expected: "data: {\"id\":1}\n\n",
		},
		{
			name:     "a trailing carriage return is trimmed",
			message:  "{\"id\":1}\r\n",
			expected: "data: {\"id\":1}\n\n",
		},
		{
			name:     "an interior carriage return is trimmed with its line",
			message:  "{\r\n\"id\":1\r\n}",
			expected: "data: {\ndata: \"id\":1\ndata: }\n\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			stream := newEventStream(recorder)

			if err := stream.send([]byte(tc.message)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if body := recorder.Body.String(); body != tc.expected {
				t.Errorf("stream wrote %q, want %q", body, tc.expected)
			}
		})
	}
}

// A quiet subscription still says something, since intermediaries and client
// idle timeouts close a connection that does not. A comment is what clients
// ignore, which is what makes it usable for that.
func TestEventStreamComment(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := newEventStream(recorder)

	if err := stream.comment(); err != nil {
		t.Fatalf("comment: %v", err)
	}
	if body := recorder.Body.String(); body != ":\n\n" {
		t.Errorf("stream wrote %q, want an empty comment line", body)
	}
}

// brokenWriter is a client that has gone away mid-stream.
type brokenWriter struct{ http.ResponseWriter }

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset by peer") }

// unflushableWriter reaches the handler through middleware that hides the
// flusher, which leaves a stream that can never be delivered.
type unflushableWriter struct{ http.ResponseWriter }

// TestEventStreamReportsAClosedStream covers both ways a write to a live stream
// fails. Either one releases the handler holding the subscription, along with
// the child slot it occupies.
func TestEventStreamReportsAClosedStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writer func(http.ResponseWriter) http.ResponseWriter
	}{
		{
			name:   "a client that has gone away",
			writer: func(w http.ResponseWriter) http.ResponseWriter { return brokenWriter{w} },
		},
		{
			name:   "a response that cannot be flushed",
			writer: func(w http.ResponseWriter) http.ResponseWriter { return unflushableWriter{w} },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stream := newEventStream(tc.writer(httptest.NewRecorder()))

			if err := stream.send([]byte(`{"id":1}`)); !errors.Is(err, errStreamClosed) {
				t.Errorf("send = %v, want %v", err, errStreamClosed)
			}
			if err := stream.comment(); !errors.Is(err, errStreamClosed) {
				t.Errorf("comment = %v, want %v", err, errStreamClosed)
			}
		})
	}
}
