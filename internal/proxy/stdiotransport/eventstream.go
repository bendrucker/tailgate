package stdiotransport

import (
	"bytes"
	"errors"
	"net/http"
	"time"
)

// keepAliveInterval is how often a quiet subscription stream emits an SSE
// comment. Intermediaries and client idle timeouts close a connection that
// says nothing, and a subscription is silent whenever nothing has changed.
const keepAliveInterval = 30 * time.Second

// errStreamClosed reports a client that is no longer reading the stream.
var errStreamClosed = errors.New("stdiotransport: subscription stream closed")

// eventStream writes SSE events to a client.
//
// Events carry no id and no retry field. This revision removed stream
// resumption, so an id would name something no client can ask for again.
type eventStream struct {
	w       http.ResponseWriter
	control *http.ResponseController
}

// newEventStream commits the SSE response headers. Committing them is what
// makes the stream visible to the client before the first event, so every
// later failure is a closed stream rather than a status still to be chosen.
func newEventStream(w http.ResponseWriter) *eventStream {
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	// Reverse proxies between tailgate and the client accumulate a response
	// they are allowed to buffer, which on a subscription means notifications
	// arrive in batches or not until it ends.
	header.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	return &eventStream{w: w, control: http.NewResponseController(w)}
}

// send writes one JSON-RPC message as an SSE data event.
func (s *eventStream) send(message []byte) error {
	// A message spanning lines would frame as several events, and the child's
	// output is newline-delimited only by convention on the way in.
	var event bytes.Buffer
	for _, line := range bytes.Split(bytes.TrimRight(message, "\r\n"), []byte("\n")) {
		event.WriteString("data: ")
		event.Write(bytes.TrimSuffix(line, []byte("\r")))
		event.WriteString("\n")
	}
	event.WriteString("\n")
	return s.write(event.Bytes())
}

// comment writes the SSE comment line that holds a quiet stream open. Clients
// ignore it, which is what makes it usable as a keep-alive.
func (s *eventStream) comment() error {
	return s.write([]byte(":\n\n"))
}

func (s *eventStream) write(raw []byte) error {
	if _, err := s.w.Write(raw); err != nil {
		return errStreamClosed
	}
	return s.flush()
}

func (s *eventStream) flush() error {
	if err := s.control.Flush(); err != nil {
		return errStreamClosed
	}
	return nil
}
