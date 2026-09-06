package stdiotransport

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// DefaultShutdownGrace is how long a child has to exit after its stdin closes
// before its process group is killed.
const DefaultShutdownGrace = 2 * time.Second

// maxLineBytes bounds one JSON-RPC message read from the child. A child that
// emits a longer line ends its own session rather than growing tailgate's heap
// without limit.
const maxLineBytes = 4 << 20

// errStdinBlocked reports a child that is alive but has stopped reading its
// stdin, so the pipe buffer filled and the write hit its deadline. It ends the
// session: the child cannot serve anything later either, and the framing of
// whatever partially reached it is already broken.
var errStdinBlocked = fmt.Errorf("%w: stdio child stopped reading stdin", proxy.ErrUpstreamTimeout)

// execConfig is the process an upstream's configuration names.
type execConfig struct {
	Command string
	Args    []string
	// Env entries ("KEY=VALUE") are appended to tailgate's own environment.
	Env []string
	Dir string
	UID int
	GID int
	// Grace is how long the child has to exit after its stdin closes before its
	// process group is killed.
	Grace time.Duration
}

// startExec returns the constructor that runs cfg as an OS process, which is
// what every configured stdio upstream gets.
func startExec(cfg execConfig) StartChild {
	return func(logger *slog.Logger) (Child, error) { return cfg.start(logger) }
}

// execChild is a Child served by a process of its own.
type execChild struct {
	cmd *exec.Cmd
	// stdin is the write end of a pipe this package creates itself, rather than
	// exec.Cmd.StdinPipe, because only an *os.File exposes the write deadline
	// that bounds Send.
	stdin  *os.File
	grace  time.Duration
	logger *slog.Logger

	messages chan []byte
	// err is written before messages closes, so a receiver that has seen the
	// close sees the error that ended the stream.
	err error
	// pipes counts the readers that must reach EOF before cmd.Wait runs, or
	// Wait closes the pipes out from under them.
	pipes  sync.WaitGroup
	exited chan struct{}

	writeMu sync.Mutex
	endOnce sync.Once

	// killMu guards reaped, which records that cmd.Wait has collected the
	// child. Signaling is unsafe from that moment: the kill path targets the
	// process group by raw pid, and the pid is free for the OS to hand to an
	// unrelated process.
	killMu sync.Mutex
	reaped bool
}

// start spawns the child and the readers draining its pipes.
func (cfg execConfig) start(logger *slog.Logger) (_ Child, err error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Dir = cfg.Dir
	cmd.Env = cfg.environ()
	isolateProcessGroup(cmd)
	if cfg.UID != 0 {
		if err := runAs(cmd, cfg.UID, cfg.GID); err != nil {
			return nil, err
		}
	}

	stdinRead, stdin, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdin = stdinRead
	defer func() {
		// The parent's copy of the read end goes once the child holds its own,
		// or closing stdin never reaches the child as EOF.
		stdinRead.Close()
		if err != nil {
			stdin.Close()
		}
	}()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		// os/exec closes the pipes it made once Start has run, but nothing has
		// started here, so the stdout pipe would outlive the attempt. An
		// upstream that fails this far in fails the same way on every request,
		// and a descriptor pair per attempt is what exhausts the process.
		stdout.Close()
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, cfg.startError(err)
	}

	c := &execChild{
		cmd:      cmd,
		stdin:    stdin,
		grace:    cfg.grace(),
		logger:   logger,
		messages: make(chan []byte),
		exited:   make(chan struct{}),
	}
	c.pipes.Add(2)
	go func() {
		defer c.pipes.Done()
		defer close(c.messages)
		c.err = scanMessages(stdout, c.messages)
	}()
	go func() {
		defer c.pipes.Done()
		logLines(stderr, logger)
	}()
	return c, nil
}

func (cfg execConfig) grace() time.Duration {
	if cfg.Grace <= 0 {
		return DefaultShutdownGrace
	}
	return cfg.Grace
}

// startError names the cause a configured uid makes likely and the error text
// does not: changing a child's uid is privileged, and a tailgate that does not
// hold that privilege can never start this upstream. The upstream is
// unavailable rather than uncontained, since nothing falls back to tailgate's
// own uid.
func (cfg execConfig) startError(err error) error {
	if cfg.UID == 0 {
		return err
	}
	return fmt.Errorf("start as uid %d gid %d, which requires privilege tailgate may not hold: %w", cfg.UID, cfg.GID, err)
}

// scanMessages splits the child's output into messages and sends each on out.
// It returns nil at EOF and the scan error otherwise: a child past
// maxLineBytes or a broken pipe leaves the stream unframed, so no later
// message can be trusted to be a whole one.
func scanMessages(stdout io.Reader, out chan<- []byte) error {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for scanner.Scan() {
		// Scanner reuses its buffer, so what goes out must be a copy.
		out <- append([]byte(nil), scanner.Bytes()...)
	}
	return scanner.Err()
}

// logLines records the child's diagnostics.
func logLines(stderr io.Reader, logger *slog.Logger) {
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 0, 4<<10), maxLineBytes)
	for scanner.Scan() {
		logger.Debug("stdio child stderr", "line", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		// Past maxLineBytes nothing further can be framed as a line, but the
		// child goes on writing, and a pipe no one drains stops it on its next
		// write with the session otherwise healthy. Reading the rest away costs
		// the diagnostics and keeps the child running.
		logger.Warn("stdio child stderr ended in error", "err", err)
		_, _ = io.Copy(io.Discard, stderr)
	}
}

func (c *execChild) Messages() <-chan []byte { return c.messages }

func (c *execChild) Err() error { return c.err }

func (c *execChild) Pid() int {
	if c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}

// Send frames one message onto the child's stdin, bounded by timeout. A child
// that stops reading fills the pipe buffer, and an unbounded write there would
// hold the request, the caller's cap slot, and shutdown behind a process that
// is never coming back.
func (c *execChild) Send(line []byte, timeout time.Duration) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.stdin.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("%w: bound write to stdio child: %v", proxy.ErrUpstreamUnavailable, err)
	}
	if _, err := c.stdin.Write(append(line, '\n')); err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return errStdinBlocked
		}
		return fmt.Errorf("%w: write to stdio child: %v", proxy.ErrUpstreamUnavailable, err)
	}
	return nil
}

// Wait reaps the child once both its pipes have reached EOF.
func (c *execChild) Wait() error {
	c.pipes.Wait()
	err := c.cmd.Wait()
	// The pid is the OS's to hand out again the moment Wait returns, so it is
	// retired as a signal target before anything that can block, and before
	// anything waiting on the exit can act on it: a grace timer firing in that
	// window would signal a process group that is no longer the child's.
	c.markReaped()
	close(c.exited)
	return err
}

func (c *execChild) Terminate() {
	c.endOnce.Do(func() {
		go func() {
			_ = c.stdin.Close()
			select {
			case <-c.exited:
			case <-time.After(c.grace):
				c.logger.Warn("stdio child ignored stdin close, killing process group")
				c.killGroup()
			}
		}()
	})
}

func (c *execChild) Kill() {
	c.endOnce.Do(func() {})
	_ = c.stdin.Close()
	c.killGroup()
}

// killGroup signals the child's process group unless the child has already
// been reaped, since its pid may since belong to something else. Holding
// killMu across the check and the signal is what leaves no window between
// them.
func (c *execChild) killGroup() {
	c.killMu.Lock()
	defer c.killMu.Unlock()
	if c.reaped {
		return
	}
	killProcessGroup(c.cmd.Process)
}

// markReaped records that cmd.Wait has collected the child, retiring its pid
// as a signal target.
func (c *execChild) markReaped() {
	c.killMu.Lock()
	defer c.killMu.Unlock()
	c.reaped = true
}

// scrubbedEnv names tailgate's tailnet auth key, which tsnet reads under both
// spellings. It is the one secret in this environment that keeps working
// wherever it is carried: a key that can join nodes to the tailnet outlives the
// host it leaked from.
var scrubbedEnv = []string{"TS_AUTHKEY", "TS_AUTH_KEY"}

// environ passes tailgate's environment plus the upstream's additions, so a
// child inherits PATH and HOME without every upstream restating them.
//
// The scrub removes the tailnet auth key and nothing else, and it is a denylist
// because a child still needs the ordinary environment to run at all. It is not
// a boundary: an upstream left at tailgate's uid reads the node state directory
// and the config file whatever the environment says, and the configured uid is
// what changes that. What the scrub buys either way is that the one long-lived
// transportable credential tailgate holds is not handed to the child.
//
// An upstream's own Env is applied afterwards, since that is the operator
// deliberately handing the child a value. Appending is also how it overrides
// one: os/exec builds the child's environment keeping the last occurrence of
// each name, so an upstream running under its own uid names its own HOME here
// rather than inheriting tailgate's, which it cannot write.
func (cfg execConfig) environ() []string {
	parent := os.Environ()
	env := make([]string, 0, len(parent)+len(cfg.Env))
	for _, entry := range parent {
		if !isScrubbed(entry) {
			env = append(env, entry)
		}
	}
	return append(env, cfg.Env...)
}

func isScrubbed(entry string) bool {
	name, _, ok := strings.Cut(entry, "=")
	return ok && slices.Contains(scrubbedEnv, name)
}

var _ Child = (*execChild)(nil)
