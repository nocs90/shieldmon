//go:build linux

package scanner

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) < 2 || os.Args[1] != launcherArg {
		return
	}
	// Exit code 126 is "found but could not run": the Runner reports stderr (redacted).
	if err := sandboxExec(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "shieldmon %s: %v\n", launcherArg, err)
		os.Exit(126)
	}
	os.Exit(0) // --check
}

// landlockMinABI is Linux 5.19: ABI 1 refuses every rename or link across directories,
// which DB updates need. ABI 2 still lacks TRUNCATE (seccomp then denies truncate(2)) and
// TCP rules (seccomp denies sockets to offline processes on every ABI).
const landlockMinABI = 2

// landlockDevices are the device files a scanner may open; nothing else under /dev.
var (
	landlockDevicesRW = []string{"/dev/null", "/dev/zero"}
	landlockDevicesR  = []string{"/dev/urandom", "/dev/random"}
)

// landlockRights are the filesystem rights by ABI: each version handles more, and a right
// the kernel does not handle cannot be restricted.
func landlockRights(abi int) uint64 {
	rights := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		rights |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		rights |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		rights |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return rights
}

// landlockFileRights are the rights that apply to a file rather than a directory.
const landlockFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

// landlockSupport returns the kernel's Landlock ABI, or why ShieldMon cannot use it.
func landlockSupport() (int, error) {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		// ENOSYS: built without Landlock; EOPNOTSUPP: not in the boot-time LSM list.
		return 0, fmt.Errorf("the kernel does not offer Landlock: %w", errno)
	}
	if int(abi) < landlockMinABI {
		return int(abi), fmt.Errorf("landlock ABI %d, need %d (Linux 5.19)", abi, landlockMinABI)
	}
	return int(abi), nil
}

// sandboxExec confines the calling process and execs the scanner. no_new_privs, Landlock and
// seccomp are per thread, so everything happens on one locked thread, which execve keeps.
func sandboxExec(args []string) error {
	spec, err := parseLaunch(args)
	if err != nil {
		return err
	}
	runtime.LockOSThread()
	abi, err := landlockSupport()
	if err != nil {
		if !spec.landlockOptional {
			return err
		}
		abi = 0 // inside bwrap: paths are confined by its mount namespace; no W^X
	}
	// no_new_privs first: without CAP_SYS_ADMIN, both landlock_restrict_self and a seccomp
	// filter require it, and fail with EPERM otherwise.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if abi > 0 {
		if err := landlockRestrict(spec, abi); err != nil {
			return err
		}
	}
	if err := limitFiles(spec.maxFileBytes); err != nil {
		return err
	}
	if err := loadSeccomp(seccompOptions{offline: !spec.net, denyTruncate: abi < 3}); err != nil {
		return err
	}
	if spec.check {
		return nil
	}
	env := os.Environ()
	if spec.scratch != "" {
		// HOME would point at the user's files, which the scanner can no longer read.
		env = slices.DeleteFunc(env, func(kv string) bool { return strings.HasPrefix(kv, "HOME=") })
		env = append(env, "HOME="+spec.scratch)
	}
	return syscall.Exec(spec.argv[0], spec.argv, env) //nolint:gosec // G204: the scanner the Runner resolved, never a shell
}

func landlockRestrict(s launchSpec, abi int) error {
	handled := landlockRights(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	if abi >= 4 && !s.net {
		// Offline processes cannot create sockets at all (seccomp); this is a second wall.
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	if abi >= 6 {
		attr.Scoped = unix.LANDLOCK_SCOPE_SIGNAL | unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // G103: the kernel ABI takes a pointer to the struct
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	ruleset := int(fd)
	defer func() { _ = unix.Close(ruleset) }()

	const read = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	// W^X: what the process can write, it cannot execute (a dropped binary or script).
	writable := handled &^ unix.LANDLOCK_ACCESS_FS_EXECUTE
	type rule struct {
		paths    []string
		access   uint64
		required bool // a policy path that is missing is an error, a system path is skipped
	}
	etc := bwrapEtc
	if s.net {
		etc = append(etc[:len(etc):len(etc)], bwrapEtcNetwork...)
	}
	rules := []rule{
		{bwrapSystemDirs, read | unix.LANDLOCK_ACCESS_FS_EXECUTE, false},
		{etc, read, false},
		{landlockDevicesRW, unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE, false},
		{landlockDevicesR, unix.LANDLOCK_ACCESS_FS_READ_FILE, false},
		{[]string{s.argv0()}, unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_EXECUTE, true},
		{s.ro, read, true},
		{s.rw, writable, true},
	}
	if s.scratch != "" {
		rules = append(rules, rule{[]string{s.scratch}, writable, true})
	}
	if s.proc {
		rules = append(rules, rule{[]string{"/proc"}, read, true})
	}
	for _, r := range rules {
		for _, path := range r.paths {
			if path == "" {
				continue
			}
			if err := landlockAllow(ruleset, path, r.access&handled); err != nil {
				if !r.required && errors.Is(err, unix.ENOENT) {
					continue
				}
				return fmt.Errorf("landlock rule %s: %w", path, err)
			}
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(ruleset), 0, 0); errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}

// argv0 is the executable the launcher will exec, which needs the execute right; in check
// mode it is the launcher itself.
func (s launchSpec) argv0() string {
	if len(s.argv) > 0 {
		return s.argv[0]
	}
	return ""
}

func landlockAllow(ruleset int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= landlockFileRights
	}
	attr := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)} //nolint:gosec // G115: file descriptors fit in int32
	if _, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&attr)), 0, 0, 0); errno != 0 { //nolint:gosec // G103: the kernel ABI takes a pointer to the struct
		return errno
	}
	return nil
}

// limitFiles bounds open files and, when maxFileBytes > 0, the size of every file written
// (a larger write fails with EFBIG and SIGXFSZ). Go programs raise their soft NOFILE limit
// to the hard one at startup, so hard limits are what count.
func limitFiles(maxFileBytes int64) error {
	type rlimit struct {
		resource int
		name     string
		max      uint64
	}
	limits := []rlimit{{unix.RLIMIT_NOFILE, "RLIMIT_NOFILE", 65536}}
	if maxFileBytes > 0 {
		limits = append(limits, rlimit{unix.RLIMIT_FSIZE, "RLIMIT_FSIZE", uint64(maxFileBytes)})
	}
	for _, l := range limits {
		var lim unix.Rlimit
		if err := unix.Getrlimit(l.resource, &lim); err != nil {
			return fmt.Errorf("%s: %w", l.name, err)
		}
		lim.Max = min(lim.Max, l.max)
		lim.Cur = min(lim.Cur, lim.Max)
		if err := unix.Setrlimit(l.resource, &lim); err != nil {
			return fmt.Errorf("%s: %w", l.name, err)
		}
	}
	return nil
}

func loadSeccomp(o seccompOptions) error {
	prog, err := seccompFilter(runtime.GOARCH, o)
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filters[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}                                                  //nolint:gosec // G115: seccompFilter stays far below BPF_MAXINSNS
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil { //nolint:gosec // G103: the kernel ABI takes a pointer to the struct
		return fmt.Errorf("seccomp: %w", err)
	}
	return nil
}
