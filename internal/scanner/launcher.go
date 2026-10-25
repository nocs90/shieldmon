package scanner

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// launcherArg is os.Args[1] of the launcher, the one confinement path of every sandbox
// backend: ShieldMon re-executes itself, sets no_new_privs, rlimits, Landlock and the seccomp
// filter on itself, then execs the scanner in place (docs/adr/0011-scanner-sandbox.md). The
// `landlock` backend runs it directly, `bwrap` inside its namespaces. It is handled before
// main runs (launcher_linux.go), so it works in any binary that links this package.
const launcherArg = "sandbox-exec"

// launcherFlags are what a backend adds to the policy on the launcher's command line.
type launcherFlags struct {
	// scratchAs is where the scratch directory appears to the process ("": its own path).
	scratchAs string
	// landlockOptional applies Landlock only where the kernel has it: bwrap already
	// confines paths, and Landlock adds W^X.
	landlockOptional bool
	// proc lets the process read /proc, which bwrap replaces with one of its PID namespace.
	proc bool
}

// launcherArgs returns the command that runs bin with args through the launcher at self.
func launcherArgs(self string, p Policy, f launcherFlags, bin string, args []string) ([]string, error) {
	if self == "" {
		return nil, errors.New("launcher executable unknown")
	}
	argv := []string{self, launcherArg}
	for _, list := range []struct {
		paths []string
		flag  string
	}{{p.ReadOnly, "--ro="}, {p.Writable, "--rw="}} {
		for _, raw := range list.paths {
			path, err := policyPath(raw)
			if err != nil {
				return nil, err
			}
			argv = append(argv, list.flag+path)
		}
	}
	if p.Scratch != "" {
		scratch, err := policyPath(p.Scratch)
		if err != nil {
			return nil, err
		}
		if f.scratchAs != "" {
			scratch = f.scratchAs
		}
		argv = append(argv, "--scratch="+scratch)
	}
	if p.Network {
		argv = append(argv, "--net")
	}
	if p.MaxFileBytes > 0 {
		argv = append(argv, "--max-file-bytes="+strconv.FormatInt(p.MaxFileBytes, 10))
	}
	if f.landlockOptional {
		argv = append(argv, "--landlock=optional")
	}
	if f.proc {
		argv = append(argv, "--proc")
	}
	argv = append(argv, "--", bin)
	return append(argv, args...), nil
}

// launchSpec is the launcher's command line.
type launchSpec struct {
	ro, rw  []string
	scratch string
	net     bool
	// maxFileBytes is RLIMIT_FSIZE (0: unchanged).
	maxFileBytes     int64
	landlockOptional bool
	proc             bool
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
		case a == "--landlock=optional":
			s.landlockOptional = true
		case a == "--proc":
			s.proc = true
		case strings.HasPrefix(a, "--ro="):
			s.ro = append(s.ro, strings.TrimPrefix(a, "--ro="))
		case strings.HasPrefix(a, "--rw="):
			s.rw = append(s.rw, strings.TrimPrefix(a, "--rw="))
		case strings.HasPrefix(a, "--scratch="):
			s.scratch = strings.TrimPrefix(a, "--scratch=")
		case strings.HasPrefix(a, "--max-file-bytes="):
			n, err := strconv.ParseInt(strings.TrimPrefix(a, "--max-file-bytes="), 10, 64)
			if err != nil || n <= 0 {
				return s, fmt.Errorf("invalid %q", a)
			}
			s.maxFileBytes = n
		default:
			return s, fmt.Errorf("unknown argument %q", a)
		}
	}
	if !s.check {
		return s, errors.New("missing -- and the scanner to run")
	}
	return s, nil
}
