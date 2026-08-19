//go:build unix

package stdiotransport

import (
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

// TestRunAs covers the credential a contained child starts under. Zero is what
// the config spells "unset", so it can never reach a Credential: a child whose
// gid fell through to zero would run in the root group.
func TestRunAs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		uid     int
		gid     int
		wantErr bool
	}{
		{name: "an ordinary uid and gid", uid: 501, gid: 20},
		{name: "root uid is refused", uid: 0, gid: 20, wantErr: true},
		{name: "root gid is refused", uid: 501, gid: 0, wantErr: true},
		{name: "negative uid is refused", uid: -1, gid: 20, wantErr: true},
		{name: "negative gid is refused", uid: 501, gid: -1, wantErr: true},
		{name: "uid past a uid_t is refused", uid: math.MaxUint32 + 1, gid: 20, wantErr: true},
		{name: "gid past a uid_t is refused", uid: 501, gid: math.MaxUint32 + 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("true")
			isolateProcessGroup(cmd)

			err := runAs(cmd, tc.uid, tc.gid)
			if (err != nil) != tc.wantErr {
				t.Fatalf("runAs(%d, %d) = %v, wantErr %v", tc.uid, tc.gid, err, tc.wantErr)
			}
			if tc.wantErr {
				if cmd.SysProcAttr.Credential != nil {
					t.Errorf("a refused credential still reached the child")
				}
				return
			}
			credential := cmd.SysProcAttr.Credential
			if credential == nil {
				t.Fatal("runAs set no credential")
			}
			if credential.Uid != uint32(tc.uid) || credential.Gid != uint32(tc.gid) {
				t.Errorf("credential = uid %d gid %d, want uid %d gid %d", credential.Uid, credential.Gid, tc.uid, tc.gid)
			}
			// An empty Groups with NoSetGroups clear is what makes the child
			// call setgroups with an empty set, dropping tailgate's own.
			if len(credential.Groups) != 0 || credential.NoSetGroups {
				t.Errorf("child keeps supplementary groups: %+v", credential)
			}
			if !cmd.SysProcAttr.Setpgid {
				t.Errorf("the credential displaced the process group isolation")
			}
		})
	}
}

// TestSpawnRefusesAUIDTailgateCannotAssume covers the failure mode a silent
// fallback would hide. Changing a child's uid is privileged, and an upstream
// configured for containment that quietly runs at tailgate's own uid is worse
// than one that never starts.
func TestSpawnRefusesAUIDTailgateCannotAssume(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can assume any uid")
	}
	// One uid this process is certainly not, since it already is not root.
	const unassumable = 1

	transport := New(Options{
		Command: os.Args[0],
		Env:     []string{fakeChildEnv + "=1"},
		Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		UID:     unassumable,
		GID:     unassumable,
	})
	t.Cleanup(func() { transport.Close() })

	s, err := transport.spawn("session", "alice")
	if err == nil {
		s.kill()
		t.Fatal("spawn started a child tailgate could not drop privilege for")
	}
	if !strings.Contains(err.Error(), "uid 1 gid 1") {
		t.Errorf("error = %q, want it to name the uid and gid asked for", err)
	}
	if !strings.Contains(err.Error(), "privilege") {
		t.Errorf("error = %q, want it to name why the start failed", err)
	}
}
