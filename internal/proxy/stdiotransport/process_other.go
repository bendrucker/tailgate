//go:build !unix

package stdiotransport

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// isolateProcessGroup is a no-op where process groups are unavailable.
func isolateProcessGroup(cmd *exec.Cmd) {}

// runAs refuses rather than starting the child at tailgate's own uid. A
// configured uid is the operator asking for containment, and a child that runs
// without it looks identical to one that runs with it.
func runAs(cmd *exec.Cmd, uid, gid int) error {
	return fmt.Errorf("stdiotransport: running a child as uid %d gid %d is unsupported on %s", uid, gid, runtime.GOOS)
}

// killProcessGroup kills the child alone. Grandchildren survive, which is why
// tailgate targets unix.
func killProcessGroup(process *os.Process) {
	if process == nil {
		return
	}
	_ = process.Kill()
}
