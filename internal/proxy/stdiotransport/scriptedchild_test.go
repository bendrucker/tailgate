package stdiotransport

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// Codes real MCP servers have been observed refusing an unknown pre-initialize
// method with. Only the first is the one the older revision was assumed to use.
const (
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeUndefined      = 0
)

// errChildKilled is what a scripted child's Wait reports after Kill, standing
// in for the signal that ends a process.
var errChildKilled = errors.New("scripted child killed")

// scriptedChild is a Child that answers in the test's own process. What it
// answers, and when, is the test's to decide, so a case that a real process
// could only approximate with sleeps and polling states its ordering directly.
type scriptedChild struct {
	logger *slog.Logger
	// answer handles one message the transport sent. It runs on a goroutine of
	// its own per message, so a request the test is holding does not stop the
	// next one from being answered.
	answer func(*scriptedChild, message)

	// messages is unbuffered, so emit returns only once the transport has taken
	// the message: a test that has emitted has been read.
	messages chan []byte

	outMu   sync.Mutex
	outDone bool
	err     error

	exitOnce sync.Once
	exited   chan struct{}
	exitErr  error

	// deaf stands in for a child that has stopped reading its stdin: the pipe
	// buffer fills, and the write holds until its deadline.
	deaf atomic.Bool
	// linger stands in for a child that ignores its stdin closing, which is
	// what leaves only the kill to end it.
	linger atomic.Bool

	sentMu sync.Mutex
	sent   []message
}

func newScriptedChild(logger *slog.Logger, answer func(*scriptedChild, message)) *scriptedChild {
	return &scriptedChild{
		logger:   logger,
		answer:   answer,
		messages: make(chan []byte),
		exited:   make(chan struct{}),
	}
}

func (c *scriptedChild) Messages() <-chan []byte { return c.messages }

func (c *scriptedChild) Err() error { return c.err }

func (c *scriptedChild) Pid() int { return 0 }

func (c *scriptedChild) Send(line []byte, timeout time.Duration) error {
	select {
	case <-c.exited:
		return fmt.Errorf("%w: write to stdio child: child has exited", proxy.ErrUpstreamUnavailable)
	default:
	}
	if c.deaf.Load() {
		// A full pipe holds the write until its deadline, or until the child
		// dies and the write fails with it.
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-c.exited:
		}
		return errStdinBlocked
	}
	msg, err := parseMessage(line)
	if err != nil {
		return fmt.Errorf("%w: scripted child was sent an unparseable message: %s", proxy.ErrUpstreamUnavailable, line)
	}
	c.sentMu.Lock()
	c.sent = append(c.sent, msg)
	c.sentMu.Unlock()
	go c.answer(c, msg)
	return nil
}

func (c *scriptedChild) Wait() error {
	<-c.exited
	return c.exitErr
}

func (c *scriptedChild) Terminate() {
	if c.linger.Load() {
		return
	}
	c.exit(nil)
}

func (c *scriptedChild) Kill() { c.exit(errChildKilled) }

func (c *scriptedChild) exit(err error) {
	c.exitOnce.Do(func() {
		c.exitErr = err
		c.endOutput(nil)
		close(c.exited)
	})
}

// endOutput ends the child's output stream. A non-nil err is what an
// unframeable line leaves behind: the process is alive and still writing, but
// nothing it says afterwards can be read as a whole message.
func (c *scriptedChild) endOutput(err error) {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	if c.outDone {
		return
	}
	c.outDone = true
	c.err = err
	close(c.messages)
}

// emit writes one message to the transport, and returns once it has been read.
// A child whose output has ended writes nothing, as a dead process does.
func (c *scriptedChild) emit(line string) {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	if c.outDone {
		return
	}
	c.messages <- []byte(line)
}

func (c *scriptedChild) result(msg message, result string) {
	c.emit(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, msg.ID, result))
}

func (c *scriptedChild) failure(msg message, code int, text string) {
	c.emit(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, msg.ID, code, text))
}

// notify emits a server-initiated notification, which is what a subscription
// stream carries.
func (c *scriptedChild) notify(seq int, echo string) {
	c.emit(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/message","params":{"seq":%d,"echo":%q}}`, seq, echo))
}

func (c *scriptedChild) messagesSent() []message {
	c.sentMu.Lock()
	defer c.sentMu.Unlock()
	return append([]message(nil), c.sent...)
}

var _ Child = (*scriptedChild)(nil)

// echoServer answers like a minimal stdio MCP server. Its era probe is
// refused the way a server that predates the method refuses an unknown one.
func echoServer(c *scriptedChild, msg message) {
	switch {
	case !msg.IsRequest():
	case msg.Method == initializeMethod:
		c.result(msg, `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"scripted-stdio-server","version":"0.0.1"}}`)
	case msg.Method == discoverMethod:
		c.failure(msg, codeMethodNotFound, "no such method")
	default:
		c.result(msg, fmt.Sprintf(`{"method":%q,"echo":%q}`, msg.Method, echoParam(msg)))
	}
}

// echoParam reads the echo the caller asked to have reflected back, which is
// what tells one request's answer from another's.
func echoParam(msg message) string {
	var envelope struct {
		Params struct {
			Echo string `json:"echo"`
		} `json:"params"`
	}
	if err := json.Unmarshal(msg.Line, &envelope); err != nil {
		return ""
	}
	return envelope.Params.Echo
}

// heldRequests answers everything the echo server does, except requests for one
// method, which it hands to the test unanswered. Waiting for one is how a test
// says "once this request has reached the child" without polling for it.
type heldRequests struct {
	method string
	held   chan message
}

func holding(method string) *heldRequests {
	return &heldRequests{method: method, held: make(chan message, 16)}
}

func (h *heldRequests) answer(c *scriptedChild, msg message) {
	if msg.Method == h.method {
		h.held <- msg
		return
	}
	echoServer(c, msg)
}

// next returns the next held request, failing the test if the child is never
// asked for one.
func (h *heldRequests) next(t *testing.T) message {
	t.Helper()
	select {
	case msg := <-h.held:
		return msg
	case <-time.After(testDeadline):
		t.Fatalf("no %s request reached the child", h.method)
		return message{}
	}
}

// childScript starts scripted children and keeps every one in the order it
// started them, so a test can drive the child a particular request spawned.
//
// The queue is unbounded, since a test that drives traffic rather than a
// particular child takes none of them and a bounded one would stall the spawn.
type childScript struct {
	answer   func(*scriptedChild, message)
	startErr error

	mu      sync.Mutex
	started []*scriptedChild
	// nudge wakes a test waiting for a child it has not seen yet.
	nudge chan struct{}
}

func newChildScript(answer func(*scriptedChild, message)) *childScript {
	return &childScript{answer: answer, nudge: make(chan struct{}, 1)}
}

func (s *childScript) start(logger *slog.Logger) (Child, error) {
	if s.startErr != nil {
		return nil, s.startErr
	}
	c := newScriptedChild(logger, s.answer)
	s.mu.Lock()
	s.started = append(s.started, c)
	s.mu.Unlock()
	select {
	case s.nudge <- struct{}{}:
	default:
	}
	return c, nil
}

func (s *childScript) take() *scriptedChild {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.started) == 0 {
		return nil
	}
	c := s.started[0]
	s.started = s.started[1:]
	return c
}

// next returns the child started for the next spawn, failing the test if
// nothing spawns one.
func (s *childScript) next(t *testing.T) *scriptedChild {
	t.Helper()
	deadline := time.After(testDeadline)
	for {
		if c := s.take(); c != nil {
			return c
		}
		select {
		case <-s.nudge:
		case <-deadline:
			t.Fatal("no child was started")
			return nil
		}
	}
}

// startedCount reports how many children this upstream has spawned and the
// test has not taken.
func (s *childScript) startedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.started)
}
