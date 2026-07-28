//go:build unix

package stdiotransport

import (
	"os"
	"os/exec"
	"syscall"
)

// isolateProcessGroup puts the child in a process group of its own. MCP stdio
// servers are commonly launched through a wrapper (npx, uv, a shell), so
// killing the immediate child alone would orphan the process actually holding
// the session.
func isolateProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the child and everything it spawned. It falls back to
// the child alone when the group is already gone.
func killProcessGroup(process *os.Process) {
	if process == nil {
		return
	}
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err != nil {
		_ = process.Kill()
	}
}
