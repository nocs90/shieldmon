package scanner

import (
	"fmt"
	"os"
)

// landlock confines scanners with the launcher alone: Landlock, seccomp and rlimits, no
// namespaces, so it runs in containers whose runtime denies them.
type landlock struct {
	self string // the ShieldMon executable, which is the launcher
}

func (l landlock) Command(p Policy, bin string, args []string) ([]string, error) {
	return launcherArgs(l.self, p, launcherFlags{}, bin, args)
}

func init() {
	RegisterSandbox(SandboxBackend{
		Name:        "landlock",
		Description: "Landlock and seccomp, for containers and Linux hosts without user namespaces: only declared paths reachable, nothing written executable, no sockets while reading image content",
		Auto:        2,
		Available:   landlockAvailable,
		New: func() Sandbox {
			self, err := os.Executable()
			if err != nil {
				return refusing{fmt.Errorf("%w: landlock: %w", ErrNoSandbox, err)}
			}
			return landlock{self: self}
		},
	})
}
