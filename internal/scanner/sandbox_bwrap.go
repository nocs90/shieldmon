package scanner

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/redact"
)

// bwrapTmpfsBytes bounds the in-memory /tmp of processes that get no scratch directory
// (the availability probe). Scanners always get a scratch directory on disk.
const bwrapTmpfsBytes = 64 << 20

// bwrapSystemDirs are mounted read-only so that the scanner and the libraries it links
// can run. On merged-/usr hosts the top-level ones are symlinks and are recreated as such.
var bwrapSystemDirs = []string{"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// bwrapEtc is the part of /etc a scanner needs: dynamic linker cache, timezone and CA
// certificates. Name resolution files are added only when the policy grants network.
var (
	bwrapEtc        = []string{"/etc/ld.so.cache", "/etc/localtime", "/etc/alternatives", "/etc/ssl", "/etc/pki", "/etc/ca-certificates"}
	bwrapEtcNetwork = []string{"/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"}
)

// apparmorUsernsSysctl is 1 on Ubuntu >= 23.10: a user namespace created by a program
// without an AppArmor profile granting "userns" has no capabilities, so bwrap cannot set
// up its sandbox.
const apparmorUsernsSysctl = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"

// bwrap confines scanners with bubblewrap: new user, mount, PID, IPC, UTS, cgroup and,
// unless the policy grants network, network namespaces; no capabilities; only system
// directories, the scanner binary and the policy's paths are visible
// (docs/adr/0011-scanner-sandbox.md).
type bwrap struct {
	path    string
	seccomp []byte // compiled filter, passed as fd 3
	lstat   func(string) (fs.FileInfo, error)
	link    func(string) (string, error)
}

func newBwrap(path string) (*bwrap, error) {
	prog, err := seccompProgram()
	if err != nil {
		return nil, err
	}
	return &bwrap{path: path, seccomp: prog, lstat: os.Lstat, link: os.Readlink}, nil
}

func (b *bwrap) Command(p Policy, bin string, args []string) (Launch, error) {
	argv, err := b.argv(p, bin, args)
	if err != nil {
		return Launch{}, err
	}
	return Launch{Argv: argv, Files: [][]byte{b.seccomp}}, nil
}

func (b *bwrap) argv(p Policy, bin string, args []string) ([]string, error) {
	if len(b.seccomp) == 0 {
		return nil, errors.New("bwrap: no seccomp filter")
	}
	// bwrap applies the filter right before it execs the scanner, after its own setup.
	argv := []string{b.path, "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--seccomp", "3"}
	if p.Network {
		argv = append(argv, "--share-net")
	}
	for _, d := range bwrapSystemDirs {
		fi, err := b.lstat(d)
		switch {
		case err != nil:
			continue
		case fi.Mode()&fs.ModeSymlink != 0:
			target, err := b.link(d)
			if err != nil {
				return nil, fmt.Errorf("bwrap: %s: %w", d, err)
			}
			argv = append(argv, "--symlink", target, d)
		case fi.IsDir():
			argv = append(argv, "--ro-bind", d, d)
		}
	}
	etc := bwrapEtc
	if p.Network {
		etc = append(etc[:len(etc):len(etc)], bwrapEtcNetwork...)
	}
	for _, f := range etc {
		argv = append(argv, "--ro-bind-try", f, f)
	}
	argv = append(argv, "--proc", "/proc", "--dev", "/dev")
	// The scratch directory is on disk: SBOM generators may unpack layers into TMPDIR,
	// which would exhaust memory on a tmpfs.
	if p.Scratch != "" {
		scratch, err := policyPath(p.Scratch)
		if err != nil {
			return nil, err
		}
		argv = append(argv, "--bind", scratch, "/tmp")
	} else {
		argv = append(argv, "--size", strconv.Itoa(bwrapTmpfsBytes), "--tmpfs", "/tmp")
	}
	// HOME would expose ~/.docker/config.json and other credentials; it is not mounted.
	argv = append(argv, "--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp")

	binds, err := bwrapBinds(p)
	if err != nil {
		return nil, err
	}
	if !underSystemDir(bin) {
		binds = append([]string{"--ro-bind", bin, bin}, binds...)
	}
	argv = append(argv, binds...)
	argv = append(argv, "--chdir", "/tmp", "--", bin)
	return append(argv, args...), nil
}

// bwrapBinds mounts the policy's paths at the same location inside the sandbox, parents
// before children so that a nested mount is not hidden. A path that is both read-only
// and writable is writable.
func bwrapBinds(p Policy) ([]string, error) {
	mode := map[string]string{}
	for _, list := range []struct {
		paths []string
		flag  string
	}{{p.ReadOnly, "--ro-bind"}, {p.Writable, "--bind"}} {
		for _, raw := range list.paths {
			path, err := policyPath(raw)
			if err != nil {
				return nil, err
			}
			mode[path] = list.flag
		}
	}
	paths := make([]string, 0, len(mode))
	for path := range mode {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		di, dj := strings.Count(paths[i], "/"), strings.Count(paths[j], "/")
		if di != dj {
			return di < dj
		}
		return paths[i] < paths[j]
	})
	var out []string
	for _, path := range paths {
		out = append(out, mode[path], path, path)
	}
	return out, nil
}

// policyPath returns the absolute, clean form of a policy path. Granting the root
// directory would defeat the sandbox and is always a bug.
func policyPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("sandbox policy: empty path")
	}
	path, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("sandbox policy: %w", err)
	}
	if path == "/" {
		return "", errors.New("sandbox policy: refusing to expose /")
	}
	return path, nil
}

func underSystemDir(path string) bool {
	for _, d := range bwrapSystemDirs {
		if strings.HasPrefix(path, d+"/") {
			return true
		}
	}
	return false
}

// bwrapAvailable starts a probe sandbox with the same arguments scanners get, so that a
// missing binary, an old release without --size, or user namespaces denied by sysctl or
// AppArmor are reported before a scan instead of during one.
func bwrapAvailable() error {
	if runtime.GOOS != "linux" {
		return errors.New("requires Linux")
	}
	path, err := exec.LookPath("bwrap")
	if err != nil {
		return errors.New("bwrap not found in PATH (install bubblewrap)")
	}
	b, err := newBwrap(path)
	if err != nil {
		return err
	}
	// The probe runs through a Runner like a scanner, so the kernel also validates the
	// seccomp filter.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := (Runner{Timeout: 10 * time.Second, Sandbox: b}).Run(ctx, path, "--version"); err != nil {
		return bwrapStartError(err, apparmorUsernsSysctl)
	}
	return nil
}

// bwrapStartError explains a failed probe, naming the fix when AppArmor restricts user
// namespaces (sysctl is the path of that setting).
func bwrapStartError(err error, sysctl string) error {
	msg := "cannot create a sandbox: " + redact.String(err.Error())
	if b, rerr := os.ReadFile(sysctl); rerr == nil && strings.TrimSpace(string(b)) == "1" {
		msg += "; AppArmor restricts user namespaces on this host (kernel.apparmor_restrict_unprivileged_userns=1):" +
			" install the bwrap profile in deploy/apparmor/shieldmon-bwrap"
	}
	return errors.New(msg)
}

func init() {
	RegisterSandbox(SandboxBackend{
		Name:        "bwrap",
		Description: "bubblewrap namespaces and seccomp on Linux hosts: no network while reading image content, only declared paths visible",
		Auto:        1,
		Available:   bwrapAvailable,
		New: func() Sandbox {
			path, err := exec.LookPath("bwrap")
			if err != nil {
				return refusing{fmt.Errorf("%w: bwrap: %w", ErrNoSandbox, err)}
			}
			b, err := newBwrap(path)
			if err != nil {
				return refusing{fmt.Errorf("%w: bwrap: %w", ErrNoSandbox, err)}
			}
			return b
		},
	})
}
