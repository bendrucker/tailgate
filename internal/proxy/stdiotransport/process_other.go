//go:build !unix

package stdiotransport

import (
	"os"
	"os/exec"
)

// isolateProcessGroup is a no-op where process groups are unavailable.
func isolateProcessGroup(cmd *exec.Cmd) {}

// killProcessGroup kills the child alone. Grandchildren survive, which is why
// tailgate targets unix.
func killProcessGroup(process *os.Process) {
	if process == nil {
		return
	}
	_ = process.Kill()
}
