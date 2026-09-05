package stdiotransport

import (
	"log/slog"
	"time"
)

// Child is one MCP server as this transport addresses it: newline-framed
// JSON-RPC messages in each direction, and a lifetime that can be ended
// gracefully or not.
//
// A configured stdio upstream is an OS process, and startExec is the
// implementation every one of them gets. The interface is where the process
// ends and the transport's own work begins: correlation, session lifecycle,
// subscription streams, and the caps around them are all reachable through a
// child that answers in the same address space.
type Child interface {
	// Send frames one message onto the child's input, bounded by timeout. A
	// child that has stopped reading fails the send with errStdinBlocked rather
	// than holding the caller for as long as the process lives.
	Send(line []byte, timeout time.Duration) error

	// Messages carries the child's output, one JSON-RPC message per receive.
	// It closes when that output ends, after which Err reports why.
	Messages() <-chan []byte

	// Err reports why the output ended, and is meaningful once Messages has
	// closed. Nil is the ordinary end of a child's output. Anything else leaves
	// the stream unframed, so no later message could be trusted to be a whole
	// one, which ends the session.
	Err() error

	// Wait collects the exited child and reports how it exited. It returns only
	// once the child's output has been consumed, so nothing it said is lost to
	// the exit.
	Wait() error

	// Terminate ends the child by closing its input, so a well-behaved server
	// exits on its own, and ends it the hard way if it does not. It returns
	// without waiting for either.
	Terminate()

	// Kill ends the child now, skipping the grace period Terminate allows.
	Kill()

	// Pid identifies a running child in the log. It is zero for a child that is
	// not a process.
	Pid() int
}

// StartChild starts the child serving one session. The logger it is handed
// already carries that session's own attributes, so the child's diagnostics are
// attributable to the session and the caller that owns it.
type StartChild func(logger *slog.Logger) (Child, error)
