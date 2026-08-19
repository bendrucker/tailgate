//go:build unix

package stdiotransport

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"syscall"
)

// isolateProcessGroup puts the child in a process group of its own. MCP stdio
// servers are commonly launched through a wrapper (npx, uv, a shell), so
// killing the immediate child alone would orphan the process actually holding
// the session.
func isolateProcessGroup(cmd *exec.Cmd) {
	procAttr(cmd).Setpgid = true
}

// runAs drops the child to uid and gid instead of tailgate's own, which is the
// only thing in this package that contains a hostile server. A child sharing
// tailgate's uid reads the node key out of the state directory, reads every
// other upstream's secrets out of the config file, and attaches to tailgate
// itself for a live bearer token, whatever its environment says.
//
// Supplementary groups go with it: naming no Groups on the Credential makes the
// child call setgroups with an empty set, so it holds the one group named here
// and none of tailgate's.
func runAs(cmd *exec.Cmd, uid, gid int) error {
	if uid <= 0 || gid <= 0 || uid > math.MaxUint32 || gid > math.MaxUint32 {
		return fmt.Errorf("stdiotransport: uid %d and gid %d must both be positive and within a uid_t", uid, gid)
	}
	procAttr(cmd).Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}
	return nil
}

func procAttr(cmd *exec.Cmd) *syscall.SysProcAttr {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	return cmd.SysProcAttr
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
