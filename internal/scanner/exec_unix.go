//go:build unix

package scanner

import (
	"os/exec"
	"syscall"
)

// setProcessGroup runs the scanner in its own process group so that a
// timeout kills the whole tree (scanners may spawn helpers).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
