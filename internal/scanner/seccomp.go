package scanner

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// The seccomp filter every sandbox backend applies to scanners (docs/adr/0011-scanner-sandbox.md,
// decision 5). It is a deny-list modelled on the container runtimes' default profile: a
// scanner parses files and spawns helpers, and needs none of the kernel interfaces below,
// which are where unprivileged kernel exploits usually start. It is generated here, in pure
// Go, because the binary is built with CGO_ENABLED=0 (no libseccomp).

// Kernel ABI constants (linux/seccomp.h, linux/filter.h, linux/audit.h, linux/sched.h).
const (
	bpfLdWAbs  = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK    = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJsetK   = 0x45 // BPF_JMP | BPF_JSET | BPF_K
	bpfRetK    = 0x06 // BPF_RET | BPF_K
	seccompNr  = 0    // offsetof(struct seccomp_data, nr)
	seccompAr  = 4    // offsetof(struct seccomp_data, arch)
	seccompA0  = 16   // offsetof(struct seccomp_data, args[0]), low 32 bits on little-endian
	retAllow   = 0x7fff0000
	retKill    = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrno   = 0x00050000
	errnoEPERM = 1
	errnoNOSYS = 38
	x32Bit     = 0x40000000 // __X32_SYSCALL_BIT

	// cloneNewMask is every CLONE_NEW* flag clone(2) takes (NS, CGROUP, UTS, IPC, USER,
	// PID, NET): clone may start threads and processes, never namespaces. CLONE_NEWTIME
	// exists only for unshare and clone3; in clone's flags its bit is the exit signal.
	cloneNewMask = 0x00020000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000
)

// sockFilter is one classic BPF instruction (struct sock_filter).
type sockFilter struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// seccompArch is what the filter needs to know about one architecture. Syscall numbers are
// per architecture; a name missing from nr does not exist there.
type seccompArch struct {
	audit uint32 // AUDIT_ARCH_*: any other value is a different ABI (i386 on amd64)
	x32   bool   // reject the x32 ABI, which shares AUDIT_ARCH_X86_64
	nr    map[string]uint32
}

// seccompArches are the architectures ShieldMon builds the filter for, keyed by GOARCH.
// TestSeccompTableMatchesKernel checks the numbers against golang.org/x/sys/unix.
var seccompArches = map[string]seccompArch{
	"amd64": {audit: 0xc000003e, x32: true, nr: map[string]uint32{
		"unshare": 272, "setns": 308, "clone": 56, "clone3": 435,
		"ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
		"mount": 165, "umount2": 166, "pivot_root": 155, "open_tree": 428, "move_mount": 429,
		"fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
		"keyctl": 250, "add_key": 248, "request_key": 249,
		"bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
		"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"init_module": 175, "finit_module": 313, "delete_module": 176,
		"kexec_load": 246, "kexec_file_load": 320, "personality": 135,
		"open_by_handle_at": 304, "reboot": 169, "swapon": 167, "swapoff": 168,
		"acct": 163, "syslog": 103, "lookup_dcookie": 212,
		"iopl": 172, "ioperm": 173, "uselib": 134,
		"socket": 41, "truncate": 76,
	}},
	"arm64": {audit: 0xc00000b7, nr: map[string]uint32{
		"unshare": 97, "setns": 268, "clone": 220, "clone3": 435,
		"ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272,
		"mount": 40, "umount2": 39, "pivot_root": 41, "open_tree": 428, "move_mount": 429,
		"fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433, "mount_setattr": 442,
		"keyctl": 219, "add_key": 217, "request_key": 218,
		"bpf": 280, "perf_event_open": 241, "userfaultfd": 282,
		"io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
		"init_module": 105, "finit_module": 273, "delete_module": 106,
		"kexec_load": 104, "kexec_file_load": 294, "personality": 92,
		"open_by_handle_at": 265, "reboot": 142, "swapon": 224, "swapoff": 225,
		"acct": 89, "syslog": 116, "lookup_dcookie": 18,
		"socket": 198, "truncate": 45,
	}},
}

// seccompDenied fail with EPERM, so that a scanner reports an error instead of dying.
var seccompDenied = []string{
	// Namespaces: the kernel code reachable as "root" in a new user namespace.
	"unshare", "setns",
	// Other processes' memory.
	"ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
	// Mounts (also needed to escape a mount namespace).
	"mount", "umount2", "pivot_root", "open_tree", "move_mount",
	"fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
	"keyctl", "add_key", "request_key",
	"bpf", "perf_event_open", "userfaultfd",
	"io_uring_setup", "io_uring_enter", "io_uring_register",
	"init_module", "finit_module", "delete_module", "kexec_load", "kexec_file_load",
	"open_by_handle_at", "reboot", "swapon", "swapoff", "acct", "syslog", "lookup_dcookie",
	"iopl", "ioperm", "uselib",
}

// seccompPersonalities are the personality(2) arguments allowed, as in the container
// runtimes' profile: query, Linux, 32-bit Linux, and the UNAME26 compatibility flag.
// Anything else (ADDR_NO_RANDOMIZE, READ_IMPLIES_EXEC, ...) weakens exploit mitigations.
var seccompPersonalities = []uint32{0x0, 0x8, 0x20000, 0x20008, 0xffffffff}

// seccompOptions vary the filter per process.
type seccompOptions struct {
	// offline denies socket(2) of every family: no TCP, UDP, or Unix socket (a host
	// socket such as the Docker daemon's), whatever else confines the network.
	offline bool
	// denyTruncate denies truncate(2) by path, for backends that cannot restrict it
	// (Landlock before ABI 3). ftruncate needs a file opened for writing.
	denyTruncate bool
}

// seccompFilter builds the filter for one architecture.
func seccompFilter(goarch string, o seccompOptions) ([]sockFilter, error) {
	a, ok := seccompArches[goarch]
	if !ok {
		return nil, fmt.Errorf("seccomp: no filter for %s (supported: amd64, arm64)", goarch)
	}
	jeq := func(k uint32, jt, jf uint8) sockFilter { return sockFilter{Code: bpfJeqK, Jt: jt, Jf: jf, K: k} }
	ld := func(off uint32) sockFilter { return sockFilter{Code: bpfLdWAbs, K: off} }
	ret := func(k uint32) sockFilter { return sockFilter{Code: bpfRetK, K: k} }

	prog := []sockFilter{
		ld(seccompAr), jeq(a.audit, 1, 0), ret(retKill),
		ld(seccompNr),
	}
	if a.x32 {
		prog = append(prog, sockFilter{Code: bpfJsetK, Jt: 0, Jf: 1, K: x32Bit}, ret(retKill))
	}
	denied := seccompDenied
	if o.offline {
		denied = append(denied[:len(denied):len(denied)], "socket")
	}
	if o.denyTruncate {
		denied = append(denied[:len(denied):len(denied)], "truncate")
	}
	for _, name := range denied {
		if n, ok := a.nr[name]; ok {
			prog = append(prog, jeq(n, 0, 1), ret(retErrno|errnoEPERM))
		}
	}
	// glibc falls back to clone when clone3 is missing; clone3's flags live in memory the
	// filter cannot read, so it cannot be allowed selectively.
	if n, ok := a.nr["clone3"]; ok {
		prog = append(prog, jeq(n, 0, 1), ret(retErrno|errnoNOSYS))
	}
	// personality: jump over the block for any other syscall; inside it, an allowed value
	// jumps to the block's final ALLOW.
	if n, ok := a.nr["personality"]; ok {
		k := len(seccompPersonalities)
		if k+3 > math.MaxUint8 {
			return nil, errors.New("seccomp: too many personalities for a BPF jump")
		}
		prog = append(prog, jeq(n, 0, uint8(k+3)), ld(seccompA0))
		for i, v := range seccompPersonalities {
			prog = append(prog, jeq(v, uint8(k-i), 0))
		}
		prog = append(prog, ret(retErrno|errnoEPERM), ret(retAllow))
	}
	// clone comes last: any other syscall jumps straight to the final ALLOW.
	n, ok := a.nr["clone"]
	if !ok {
		return nil, fmt.Errorf("seccomp: %s has no clone syscall number", goarch)
	}
	prog = append(prog,
		jeq(n, 0, 3), ld(seccompA0),
		sockFilter{Code: bpfJsetK, Jt: 0, Jf: 1, K: cloneNewMask}, ret(retErrno|errnoEPERM),
		ret(retAllow))
	return prog, nil
}

// seccompProgram returns the filter for goarch (runtime.GOARCH: the scanner runs on the
// same kernel ABI as ShieldMon) as the bytes of a struct sock_filter array, which is what
// bwrap --seccomp reads.
func seccompProgram(goarch string, o seccompOptions) ([]byte, error) {
	prog, err := seccompFilter(goarch, o)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, prog); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
