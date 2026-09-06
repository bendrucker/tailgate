package stdiotransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// errDuplicateRequestID rejects a second in-flight request reusing a live
// JSON-RPC id, which would let one request steal another's response. Every id
// correlated on is minted here, so no caller can reach this: it is the
// invariant the minting upholds.
var errDuplicateRequestID = errors.New("stdiotransport: duplicate in-flight JSON-RPC id")

// session is one MCP session and the child serving it. The session id is bound
// to the identity that created it: the child is that caller's, and no other
// caller can reach it.
type session struct {
	id      string
	subject string
	logger  *slog.Logger

	child  Child
	exited chan struct{}

	mu      sync.Mutex
	pending map[string]chan []byte
	// listeners are the open subscription streams the child's notifications
	// fan out to. They exist only under a stateless revision, where a
	// subscriptions/listen response stream is the sole path a server-initiated
	// notification has back to a client.
	listeners map[int64]*listener
	nextKey   int64

	// ids mints the correlation ids tailgate substitutes for a caller's own.
	ids atomic.Uint64

	lastUsed atomic.Int64
	active   atomic.Int64

	// removed is guarded by the owning Transport's mutex, which is what makes
	// registration and teardown of a session that dies during spawn ordered.
	removed bool
}

// spawn starts the child and the goroutine draining its output. The caller owns
// supervision: nothing reaps the child until the transport starts it.
func (t *Transport) spawn(id string, subject string) (*session, error) {
	logger := t.logger.With("session", id, "sub", subject)
	child, err := t.options.StartChild(logger)
	if err != nil {
		return nil, err
	}

	s := &session{
		id:        id,
		subject:   subject,
		logger:    logger,
		child:     child,
		exited:    make(chan struct{}),
		pending:   make(map[string]chan []byte),
		listeners: make(map[int64]*listener),
	}
	s.touch()
	go t.readChild(s)
	return s, nil
}

// readChild fans the child's output out to the requests waiting on it, and
// ends the session when that output ends in error: nothing can correlate a
// response any more, so leaving the session registered would strand every later
// request on the request timeout and hold the caller's cap slot.
func (t *Transport) readChild(s *session) {
	// The child's output is the only source a subscription stream has, so its
	// end is theirs. The handlers holding them are released here, since nothing
	// will write to their channels again.
	defer s.closeAllListeners()
	for line := range s.child.Messages() {
		s.deliver(line)
	}
	if err := s.child.Err(); err != nil {
		s.logger.Warn("stdio child output ended in error", "err", err)
		t.removeSession(s)
	}
}

func (s *session) deliver(line []byte) {
	msg, err := parseMessage(line)
	if err != nil {
		s.logger.Warn("stdio child emitted an unparseable message")
		return
	}
	if msg.IsNotification() {
		s.broadcast(msg.Line)
		return
	}
	if !msg.IsResponse() {
		// A server-initiated request has no HTTP response to ride on. Revisions
		// that allowed one carried it on a stream this transport never opens,
		// and 2026-07-28 removed the direction outright in favor of MRTR, where
		// the server asks for input inside its own result.
		s.logger.Debug("dropping server-initiated request from stdio child", "method", msg.Method)
		return
	}

	// The send happens under the lock, into a buffered channel that cannot
	// block. A waiter giving up therefore sees either its own live pending
	// entry or a response already in hand, never a response lost in between.
	s.mu.Lock()
	waiter, ok := s.pending[msg.Key]
	if ok {
		delete(s.pending, msg.Key)
		waiter <- msg.Line
	}
	s.mu.Unlock()
	if !ok {
		s.logger.Debug("stdio child answered an unknown request id")
	}
}

// request carries a caller's request to the child under an id tailgate mints,
// and restores the caller's own id on the answer.
//
// Every caller's request is rewritten, because a caller's id space is not
// tailgate's to trust. Independent POSTs may all call themselves id 1, and a
// caller that hangs up mid-request and retries reuses an id the child is still
// working on. Correlating on the caller's id would let either request take the
// other's answer.
func (s *session) request(ctx context.Context, msg message, timeout time.Duration) ([]byte, error) {
	line, key, err := s.substitute(msg.Line)
	if err != nil {
		return nil, err
	}
	response, err := s.exchange(ctx, message{Line: line, Method: msg.Method, Key: key}, timeout)
	if err != nil {
		return nil, err
	}
	return setID(response, msg.ID)
}

// mintID returns an id no caller can collide with, and the correlation key for
// it, so the two are always derived together. Every id this transport
// correlates on comes from here, whether it carries a caller's request or one
// tailgate originates.
func (s *session) mintID() (json.RawMessage, string) {
	id := json.RawMessage(strconv.Quote("tailgate-" + strconv.FormatUint(s.ids.Add(1), 10)))
	return id, correlationKey(id)
}

// substitute rewrites a caller's message under a minted id and reports the key
// its answer will correlate on.
func (s *session) substitute(line []byte) ([]byte, string, error) {
	minted, key := s.mintID()
	rewritten, err := setID(line, minted)
	if err != nil {
		return nil, "", err
	}
	return rewritten, key, nil
}

// call issues a request tailgate originates on its own behalf rather than one
// it carries for a caller, which is how the child's era is settled before any
// caller's message reaches it.
func (s *session) call(ctx context.Context, method string, params any, timeout time.Duration) ([]byte, error) {
	minted, key := s.mintID()
	line, err := json.Marshal(map[string]any{
		"jsonrpc": jsonrpcVersion,
		"id":      minted,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, errInvalidMessage
	}
	return s.exchange(ctx, message{Line: line, Method: method, Key: key}, timeout)
}

// subscribe carries a caller's request to the child without waiting for its
// answer, and reports the channel that answer will arrive on.
//
// It exists for the one method whose response completes the stream rather than
// the request: the send is bounded by timeout, but the answer may not come for
// as long as the subscription lasts, so the wait belongs to the handler
// relaying the stream rather than to an exchange deadline. release must run
// when that handler returns.
func (s *session) subscribe(msg message, timeout time.Duration) (<-chan []byte, func(), error) {
	line, key, err := s.substitute(msg.Line)
	if err != nil {
		return nil, nil, err
	}

	waiter := make(chan []byte, 1)
	s.mu.Lock()
	if _, duplicate := s.pending[key]; duplicate {
		s.mu.Unlock()
		return nil, nil, errDuplicateRequestID
	}
	s.pending[key] = waiter
	s.mu.Unlock()

	release := func() {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
	}
	if err := s.send(line, timeout); err != nil {
		release()
		return nil, nil, err
	}
	return waiter, release, nil
}

// notify sends a one-way message tailgate originates.
func (s *session) notify(method string, params any, timeout time.Duration) error {
	line, err := json.Marshal(map[string]any{
		"jsonrpc": jsonrpcVersion,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return errInvalidMessage
	}
	return s.send(line, timeout)
}

// exchange sends a request and waits for the child's answer to it.
func (s *session) exchange(ctx context.Context, msg message, timeout time.Duration) ([]byte, error) {
	waiter := make(chan []byte, 1)
	s.mu.Lock()
	if _, duplicate := s.pending[msg.Key]; duplicate {
		s.mu.Unlock()
		return nil, errDuplicateRequestID
	}
	s.pending[msg.Key] = waiter

	// abandon reports a failed wait, unless the response landed as the wait was
	// giving up.
	abandon := func(err error) ([]byte, error) {
		s.mu.Lock()
		_, waiting := s.pending[msg.Key]
		delete(s.pending, msg.Key)
		s.mu.Unlock()
		if !waiting {
			return <-waiter, nil
		}
		return nil, err
	}
	s.mu.Unlock()

	if err := s.send(msg.Line, timeout); err != nil {
		return abandon(err)
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case response := <-waiter:
		return response, nil
	case <-s.exited:
		return abandon(fmt.Errorf("%w: stdio child exited", proxy.ErrUpstreamUnavailable))
	case <-timer.C:
		return abandon(proxy.ErrUpstreamTimeout)
	case <-ctx.Done():
		return abandon(context.Cause(ctx))
	}
}

func (s *session) send(line []byte, timeout time.Duration) error {
	return s.child.Send(line, timeout)
}

func (s *session) terminate() { s.child.Terminate() }

func (s *session) kill() { s.child.Kill() }

func (s *session) touch() { s.lastUsed.Store(time.Now().UnixNano()) }

func (s *session) begin() {
	s.active.Add(1)
	s.touch()
}

// finish records the completion time before releasing the request, so the
// reaper never sees an idle session with a stale timestamp.
func (s *session) finish() {
	s.touch()
	s.active.Add(-1)
}

func (s *session) idleSince(now time.Time, timeout time.Duration) bool {
	if s.active.Load() > 0 {
		return false
	}
	return now.Sub(time.Unix(0, s.lastUsed.Load())) >= timeout
}
