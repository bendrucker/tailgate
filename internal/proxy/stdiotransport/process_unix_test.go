//go:build unix

package stdiotransport

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestKillReachesGrandchildren covers the wrapper case: the configured command
// is a launcher (npx, uv, a shell) and the process actually serving MCP is its
// child. Killing only the immediate child would leave that one running.
func TestKillReachesGrandchildren(t *testing.T) {
	h := newHarness(t, Options{Env: []string{
		fakeChildGrandchild + "=1",
		fakeChildLinger + "=1",
	}})
	h.transport.shutdownGrace = 50 * time.Millisecond

	response := h.do(t, call{subject: "alice", body: initializeBody})
	session := response.Header.Get(sessionHeader)
	result, _ := decodeMessage(t, response)["result"].(map[string]any)
	response.Body.Close()

	pid, ok := result["grandchildPid"].(float64)
	if !ok || pid == 0 {
		t.Fatalf("fake child reported no grandchild: %v", result)
	}

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	deleted := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	deleted.Body.Close()

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("child was never killed")
	}
	waitFor(t, "the grandchild to die with its process group", func() bool {
		return syscall.Kill(int(pid), 0) == syscall.ESRCH
	})
}

// TestChildGetsAnOrdinaryStdin covers the pipe the transport builds itself so
// that send can carry a write deadline. What the child gets must still be an
// ordinary blocking stdin that reaches EOF when the session ends, and a POSIX
// shell shows both: its read fails outright on a non-blocking descriptor, and
// it exits on EOF rather than waiting out the kill.
func TestChildGetsAnOrdinaryStdin(t *testing.T) {
	h := newHarness(t, Options{
		Command: "/bin/sh",
		Args: []string{"-c", `read line
printf '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25"}}\n'
while read line; do :; done`},
	})
	// Long enough that a killed child is unmistakable next to one that exited
	// on EOF.
	h.transport.shutdownGrace = 30 * time.Second
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	// The read end is the child's once it is started, and a copy left open in
	// the parent is a descriptor leaked per session.
	if _, err := child.cmd.Stdin.(*os.File).Stat(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("the parent kept its copy of the child's stdin: %v", err)
	}

	deleted := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	deleted.Body.Close()

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("closing stdin never reached the child as EOF")
	}
	if code := child.cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("expected the child to exit on EOF, got exit code %d", code)
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

			s := &session{
				cmd:    bystander,
				stdin:  stdin,
				logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
				exited: make(chan struct{}),
			}
			if tc.reaped {
				s.markReaped()
			}
			s.kill()

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
// goroutine that wakes on exited, such as terminate's grace timer losing its
// select, must already see the pid retired.
func TestReapingPrecedesTheExitBroadcast(t *testing.T) {
	h := newHarness(t, Options{})
	session := h.initialize(t, "alice")

	h.transport.mu.Lock()
	child := h.transport.sessions[session]
	h.transport.mu.Unlock()

	response := h.do(t, call{method: http.MethodDelete, subject: "alice", session: session})
	response.Body.Close()

	select {
	case <-child.exited:
	case <-time.After(10 * time.Second):
		t.Fatal("DELETE did not end the child process")
	}
	child.killMu.Lock()
	defer child.killMu.Unlock()
	if !child.reaped {
		t.Fatal("the child was announced as exited before its pid was retired")
	}
}
