//go:build linux

package scannertest

import (
	"os"
	"os/exec"
	"syscall"
)

// probeUserns starts a child in a new user namespace. It uses clone(CLONE_NEWUSER), not
// unshare: unshare(CLONE_NEWUSER) always fails with EINVAL in a multithreaded process.
func probeUserns() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, probeArg, "noop") //nolint:gosec // G204: the test binary re-running itself as a probe
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}
	return cmd.Run()
}

// probePersonality turns off address space randomization for the probe process.
func probePersonality() error {
	const addrNoRandomize = 0x0040000
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PERSONALITY, addrNoRandomize, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
