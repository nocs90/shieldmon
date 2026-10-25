package scanner

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// landlockExecArg is os.Args[1] of the launcher: ShieldMon re-executes itself, applies
// Landlock, rlimits, no_new_privs and the seccomp filter to itself, then execs the scanner
// in place (docs/adr/0011-scanner-sandbox.md, decision 4). It is handled before main runs
// (sandbox_landlock_linux.go), so it works in any binary that links this package.
const landlockExecArg = "sandbox-exec"

// landlock confines scanners with the Landlock LSM: no namespaces, so it runs in
// containers whose runtime denies them.
type landlock struct {
	self string // the ShieldMon executable, which is the launcher
}

func (l landlock) Command(p Policy, bin string, args []string) (Launch, error) {
	if l.self == "" {
		return Launch{}, errors.New("landlock: launcher executable unknown")
	}
	argv := []string{l.self, landlockExecArg}
	for _, list := range []struct {
		paths []string
		flag  string
	}{{p.ReadOnly, "--ro="}, {p.Writable, "--rw="}} {
		for _, raw := range list.paths {
			path, err := policyPath(raw)
			if err != nil {
				return Launch{}, err
			}
			argv = append(argv, list.flag+path)
		}
	}
	if p.Scratch != "" {
		scratch, err := policyPath(p.Scratch)
		if err != nil {
			return Launch{}, err
		}
		argv = append(argv, "--scratch="+scratch)
	}
	if p.Network {
		argv = append(argv, "--net")
	}
	argv = append(argv, "--", bin)
	return Launch{Argv: append(argv, args...)}, nil
}

// launchSpec is the launcher's command line.
type launchSpec struct {
	ro, rw  []string
	scratch string
	net     bool
	// check applies the confinement and exits instead of exec'ing: the availability probe.
	check bool
	argv  []string // the scanner and its arguments; argv[0] is an absolute path
}

func parseLaunch(args []string) (launchSpec, error) {
	var s launchSpec
	for i, a := range args {
		switch {
		case a == "--":
			s.argv = args[i+1:]
			if len(s.argv) == 0 || !strings.HasPrefix(s.argv[0], "/") {
				return s, errors.New("an absolute scanner path must follow --")
			}
			return s, nil
		case a == "--net":
			s.net = true
		case a == "--check":
			s.check = true
		case strings.HasPrefix(a, "--ro="):
			s.ro = append(s.ro, strings.TrimPrefix(a, "--ro="))
		case strings.HasPrefix(a, "--rw="):
			s.rw = append(s.rw, strings.TrimPrefix(a, "--rw="))
		case strings.HasPrefix(a, "--scratch="):
			s.scratch = strings.TrimPrefix(a, "--scratch=")
		default:
			return s, fmt.Errorf("unknown argument %q", a)
		}
	}
	if !s.check {
		return s, errors.New("missing -- and the scanner to run")
	}
	return s, nil
}

func init() {
	RegisterSandbox(SandboxBackend{
		Name:        "landlock",
		Description: "Landlock and seccomp, for containers and Linux hosts without user namespaces: only declared paths reachable, no sockets while reading image content",
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
