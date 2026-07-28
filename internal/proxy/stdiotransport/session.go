package stdiotransport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// maxLineBytes bounds one JSON-RPC message read from the child. A child that
// emits a longer line ends its own session rather than growing tailgate's heap
// without limit.
const maxLineBytes = 4 << 20

// errDuplicateRequestID rejects a second in-flight request reusing a live
// JSON-RPC id, which JSON-RPC forbids and which would otherwise let one
// request steal another's response.
var errDuplicateRequestID = errors.New("stdiotransport: duplicate in-flight JSON-RPC id")

// session is one MCP session and the child process serving it. The session id
// is bound to the identity that created it: the child is that caller's, and no
// other caller can reach it.
type session struct {
	id      string
	subject string
	grace   time.Duration
	logger  *slog.Logger

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	pipes  sync.WaitGroup
	exited chan struct{}

	writeMu sync.Mutex

	// killMu guards reaped, which records that cmd.Wait has collected the
	// child. Signaling is unsafe from that moment: the kill path targets the
	// process group by raw pid, and the pid is free for the OS to hand to an
	// unrelated process.
	killMu sync.Mutex
	reaped bool

	mu      sync.Mutex
	pending map[string]chan []byte

	lastUsed atomic.Int64
	active   atomic.Int64

	terminateOnce sync.Once

	// removed is guarded by the owning Transport's mutex, which is what makes
	// registration and teardown of a session that dies during spawn ordered.
	removed bool
}

// spawn starts the child and its pipe readers. The caller owns supervision:
// nothing reaps the process until the transport starts it.
func (t *Transport) spawn(id string, subject string) (*session, error) {
	cmd := exec.Command(t.options.Command, t.options.Args...)
	cmd.Dir = t.options.Dir
	cmd.Env = t.childEnv()
	isolateProcessGroup(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	s := &session{
		id:      id,
		subject: subject,
		grace:   t.shutdownGrace,
		logger:  t.logger.With("session", id, "sub", subject),
		cmd:     cmd,
		stdin:   stdin,
		exited:  make(chan struct{}),
		pending: make(map[string]chan []byte),
	}
	s.touch()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Both pipes must reach EOF before cmd.Wait runs, or Wait closes them out
	// from under the readers.
	s.pipes.Add(2)
	go func() {
		defer s.pipes.Done()
		if err := s.readMessages(stdout); err != nil {
			// Nothing can correlate a response any more, so the session is
			// over. Leaving it registered would strand every later request on
			// the request timeout and hold the caller's cap slot.
			s.logger.Warn("stdio child output ended in error", "err", err)
			t.removeSession(s)
		}
	}()
	go func() {
		defer s.pipes.Done()
		s.logStderr(stderr)
	}()
	return s, nil
}

// readMessages fans the child's newline-delimited output out to the requests
// waiting on it. It returns nil at EOF and the scan error otherwise, which
// ends the session: a child past maxLineBytes or a broken pipe leaves the
// stream unframed, so no later message can be trusted to be a whole one.
func (s *session) readMessages(stdout io.Reader) error {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for scanner.Scan() {
		// Scanner reuses its buffer, so the delivered response must be a copy.
		s.deliver(append([]byte(nil), scanner.Bytes()...))
	}
	return scanner.Err()
}

func (s *session) deliver(line []byte) {
	msg, err := parseMessage(line)
	if err != nil {
		s.logger.Warn("stdio child emitted an unparseable message")
		return
	}
	if !msg.IsResponse() {
		// Server-initiated requests and notifications have no HTTP response to
		// ride on: this transport answers each POST with the single JSON
		// object the spec allows, so there is no open stream to carry them.
		s.logger.Debug("dropping unsolicited message from stdio child", "method", msg.Method)
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

func (s *session) logStderr(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 0, 4<<10), maxLineBytes)
	for scanner.Scan() {
		s.logger.Debug("stdio child stderr", "line", scanner.Text())
	}
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

	if err := s.send(msg.Line); err != nil {
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

// send frames one message onto the child's stdin.
func (s *session) send(line []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.stdin.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("%w: write to stdio child: %v", proxy.ErrUpstreamUnavailable, err)
	}
	return nil
}

// terminate ends the session's child: stdin closes so a well-behaved server
// exits on its own, and the process group is killed if it does not.
func (s *session) terminate() {
	s.terminateOnce.Do(func() {
		go func() {
			_ = s.stdin.Close()
			select {
			case <-s.exited:
			case <-time.After(s.grace):
				s.logger.Warn("stdio child ignored stdin close, killing process group")
				s.killChild()
			}
		}()
	})
}

// kill ends the child now, skipping the grace period terminate allows.
func (s *session) kill() {
	s.terminateOnce.Do(func() {})
	_ = s.stdin.Close()
	s.killChild()
}

// killChild signals the child's process group unless the child has already
// been reaped, since its pid may since belong to something else. Holding
// killMu across the check and the signal is what leaves no window between
// them.
func (s *session) killChild() {
	s.killMu.Lock()
	defer s.killMu.Unlock()
	if s.reaped {
		return
	}
	killProcessGroup(s.cmd.Process)
}

// markReaped records that cmd.Wait has collected the child, retiring its pid
// as a signal target.
func (s *session) markReaped() {
	s.killMu.Lock()
	defer s.killMu.Unlock()
	s.reaped = true
}

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
