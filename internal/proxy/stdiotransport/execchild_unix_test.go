//go:build unix

package stdiotransport

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bendrucker/tailgate/internal/proxy"
)

// runningChild is an execChild with its Wait running, which is how the
// transport runs one: the exit is collected on a goroutine of its own, and
// nothing observes it before then.
type runningChild struct {
	*execChild
	// done closes once Wait has returned and err holds its result.
	done chan struct{}
	err  error
}

func startShell(t *testing.T, cfg execConfig, script string) *runningChild {
	t.Helper()
	cfg.Command = "/bin/sh"
	cfg.Args = []string{"-c", script}

	started, err := startExec(cfg)(testLogger())
	if err != nil {
		t.Fatalf("start the child: %v", err)
	}
	c := &runningChild{execChild: started.(*execChild), done: make(chan struct{})}
	go func() {
		defer close(c.done)
		c.err = c.execChild.Wait()
	}()
	t.Cleanup(func() {
		c.Kill()
		awaitClose(t, c.done, "the child to be reaped")
	})
	return c
}

func (c *runningChild) receive(t *testing.T) string {
	t.Helper()
	select {
	case line, ok := <-c.Messages():
		if !ok {
			t.Fatalf("the child's output ended: %v", c.Err())
		}
		return string(line)
	case <-time.After(testDeadline):
		t.Fatal("the child said nothing")
		return ""
	}
}

// TestChildGetsAnOrdinaryStdin covers the pipe this package builds itself so
// that Send can carry a write deadline. What the child gets must still be an
// ordinary blocking stdin that reaches EOF when the session ends, and a POSIX
// shell shows both: its read fails outright on a non-blocking descriptor, and
// it exits on EOF rather than waiting out the kill.
func TestChildGetsAnOrdinaryStdin(t *testing.T) {
	// A grace long enough that a killed child is unmistakable next to one that
	// exited on EOF.
	c := startShell(t, execConfig{Grace: time.Hour}, `while read line; do printf '%s\n' "$line"; done`)

	// The read end is the child's once it is started, and a copy left open in
	// the parent is a descriptor leaked per session.
	if _, err := c.cmd.Stdin.(*os.File).Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the parent kept its copy of the child's stdin: %v", err)
	}

	const request = `{"jsonrpc":"2.0","id":1}`
	if err := c.Send([]byte(request), testDeadline); err != nil {
		t.Fatalf("send: %v", err)
	}
	if answer := c.receive(t); answer != request {
		t.Errorf("the child read %q, want %q", answer, request)
	}

	c.Terminate()
	awaitClose(t, c.done, "the child to exit on EOF")
	if c.err != nil {
		t.Fatalf("expected a clean exit on EOF, got %v", c.err)
	}
}

// TestTerminateKillsAChildThatIgnoresStdin covers the other end of the grace
// period, and with it the wrapper case: the configured command is a launcher
// (npx, uv, a shell) and the process actually serving MCP is its child, so
// killing the immediate child alone would leave that one running.
func TestTerminateKillsAChildThatIgnoresStdin(t *testing.T) {
	c := startShell(t, execConfig{Grace: 50 * time.Millisecond}, `sleep 300 &
printf '{"grandchild":%s}\n' "$!"
while :; do sleep 300; done`)

	var announced struct {
		Grandchild int `json:"grandchild"`
	}
	if err := json.Unmarshal([]byte(c.receive(t)), &announced); err != nil {
		t.Fatalf("decode the child's announcement: %v", err)
	}
	if announced.Grandchild == 0 {
		t.Fatal("the child reported no grandchild")
	}

	c.Terminate()
	awaitClose(t, c.done, "the grace period to run out and the child to be killed")
	if c.err == nil {
		t.Error("expected the killed child to report how it ended")
	}
	waitFor(t, "the grandchild to die with its process group", func() bool {
		return syscall.Kill(announced.Grandchild, 0) == syscall.ESRCH
	})
}

// TestSendToAChildThatStoppedReadingIsBounded covers the write deadline. A
// child that stays alive but stops reading its stdin fills the pipe buffer, and
// an unbounded write there would hold the request, the caller's cap slot, and
// shutdown behind a process that is never coming back.
func TestSendToAChildThatStoppedReadingIsBounded(t *testing.T) {
	c := startShell(t, execConfig{}, `while :; do sleep 300; done`)

	// Larger than any pipe buffer, so the write cannot complete without the
	// child reading.
	line := []byte(strings.Repeat("x", 4<<20))
	err := c.Send(line, 50*time.Millisecond)
	if !errors.Is(err, errStdinBlocked) {
		t.Fatalf("send = %v, want %v", err, errStdinBlocked)
	}
	if !errors.Is(err, proxy.ErrUpstreamTimeout) {
		t.Errorf("send = %v, want it to report a timeout to the caller", err)
	}
}

// TestStderrFloodLeavesTheChildServing covers a child whose diagnostics run
// past the framing limit. Its stderr is a pipe like any other: one nobody reads
// stops the child on its next write, so the session it is serving dies of a log
// line.
func TestStderrFloodLeavesTheChildServing(t *testing.T) {
	c := startShell(t, execConfig{}, `dd if=/dev/zero bs=65536 count=128 2>/dev/null | tr '\0' 'x' >&2
while read line; do printf '%s\n' "$line"; done`)

	const request = `{"jsonrpc":"2.0","id":1}`
	if err := c.Send([]byte(request), testDeadline); err != nil {
		t.Fatalf("send: %v", err)
	}
	if answer := c.receive(t); answer != request {
		t.Errorf("the child read %q, want %q", answer, request)
	}
}

// TestKillSkipsAReapedChild covers the pid-reuse hazard in the kill path. The
// group kill is a raw signal on cmd.Process.Pid, which bypasses the
// done-tracking that makes os.Process.Kill safe after Wait, so once the child
// is reaped that pid may belong to an unrelated process group. The bystander
// here stands in for the process that inherited it.
func TestKillSkipsAReapedChild(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reaped    bool
		wantAlive bool
	}{
		{
			name:      "a live child is killed",
			reaped:    false,
			wantAlive: false,
		},
		{
			name:      "a reaped pid is left alone",
			reaped:    true,
			wantAlive: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bystander := exec.Command("sleep", "30")
			isolateProcessGroup(bystander)
			if err := bystander.Start(); err != nil {
				t.Fatalf("start bystander: %v", err)
			}
			exited := make(chan struct{})
			go func() {
				_ = bystander.Wait()
				close(exited)
			}()
			t.Cleanup(func() {
				_ = bystander.Process.Kill()
				<-exited
			})

			stdinRead, stdin, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}
			t.Cleanup(func() { stdinRead.Close() })

			c := &execChild{
				cmd:    bystander,
				stdin:  stdin,
				logger: testLogger(),
				exited: make(chan struct{}),
			}
			if tc.reaped {
				c.markReaped()
			}
			c.Kill()

			select {
			case <-exited:
				if tc.wantAlive {
					t.Fatal("kill signaled a pid the child no longer owned")
				}
			case <-time.After(500 * time.Millisecond):
				if !tc.wantAlive {
					t.Fatal("kill left a live child running")
				}
			}
		})
	}
}

// TestReapingPrecedesTheExitBroadcast is what makes the kill guard reliable: a
// goroutine that wakes on the exit, such as Terminate's grace timer losing its
// select, must already see the pid retired.
func TestReapingPrecedesTheExitBroadcast(t *testing.T) {
	c := startShell(t, execConfig{Grace: time.Hour}, `while read line; do :; done`)

	c.Terminate()
	awaitClose(t, c.exited, "the child to exit")

	c.killMu.Lock()
	defer c.killMu.Unlock()
	if !c.reaped {
		t.Fatal("the child was announced as exited before its pid was retired")
	}
}

// TestStartRefusesAUIDTailgateCannotAssume covers the failure mode a silent
// fallback would hide. Changing a child's uid is privileged, and an upstream
// configured for containment that quietly runs at tailgate's own uid is worse
// than one that never starts.
func TestStartRefusesAUIDTailgateCannotAssume(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can assume any uid")
	}
	// One uid this process is certainly not, since it already is not root.
	const unassumable = 1

	child, err := startExec(execConfig{Command: "/bin/sh", Args: []string{"-c", "exit 0"}, UID: unassumable, GID: unassumable})(testLogger())
	if err == nil {
		child.Kill()
		t.Fatal("start ran a child tailgate could not drop privilege for")
	}
	if !strings.Contains(err.Error(), "uid 1 gid 1") {
		t.Errorf("error = %q, want it to name the uid and gid asked for", err)
	}
	if !strings.Contains(err.Error(), "privilege") {
		t.Errorf("error = %q, want it to name why the start failed", err)
	}
}
