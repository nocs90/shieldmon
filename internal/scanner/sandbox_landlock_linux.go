//go:build linux

package scanner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/nocs90/shieldmon/internal/redact"
)

func landlockAvailable() error {
	abi, err := landlockSupport()
	if err != nil {
		return err
	}
	if _, err := seccompFilter(runtime.GOARCH, seccompOptions{}); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	// The probe confines a process twice, through the launcher like a scanner and with
	// --check: the kernel validates the ruleset and the seccomp filter, and the launcher
	// can exec ShieldMon itself.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := Runner{Timeout: 10 * time.Second, Sandbox: landlock{self: self}}
	if _, err := r.Run(ctx, self, launcherArg, "--check"); err != nil {
		return fmt.Errorf("cannot confine a process (Landlock ABI %d): %s", abi, redact.String(err.Error()))
	}
	return nil
}
