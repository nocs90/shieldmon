package scanner

import "golang.org/x/sys/unix"

const kernelAuditArch = unix.AUDIT_ARCH_X86_64

var kernelSyscalls = map[string]uintptr{
	"unshare": unix.SYS_UNSHARE, "setns": unix.SYS_SETNS, "clone": unix.SYS_CLONE, "clone3": unix.SYS_CLONE3,
	"ptrace": unix.SYS_PTRACE, "process_vm_readv": unix.SYS_PROCESS_VM_READV, "process_vm_writev": unix.SYS_PROCESS_VM_WRITEV, "kcmp": unix.SYS_KCMP,
	"mount": unix.SYS_MOUNT, "umount2": unix.SYS_UMOUNT2, "pivot_root": unix.SYS_PIVOT_ROOT, "open_tree": unix.SYS_OPEN_TREE, "move_mount": unix.SYS_MOVE_MOUNT,
	"fsopen": unix.SYS_FSOPEN, "fsconfig": unix.SYS_FSCONFIG, "fsmount": unix.SYS_FSMOUNT, "fspick": unix.SYS_FSPICK, "mount_setattr": unix.SYS_MOUNT_SETATTR,
	"keyctl": unix.SYS_KEYCTL, "add_key": unix.SYS_ADD_KEY, "request_key": unix.SYS_REQUEST_KEY,
	"bpf": unix.SYS_BPF, "perf_event_open": unix.SYS_PERF_EVENT_OPEN, "userfaultfd": unix.SYS_USERFAULTFD,
	"io_uring_setup": unix.SYS_IO_URING_SETUP, "io_uring_enter": unix.SYS_IO_URING_ENTER, "io_uring_register": unix.SYS_IO_URING_REGISTER,
	"init_module": unix.SYS_INIT_MODULE, "finit_module": unix.SYS_FINIT_MODULE, "delete_module": unix.SYS_DELETE_MODULE,
	"kexec_load": unix.SYS_KEXEC_LOAD, "kexec_file_load": unix.SYS_KEXEC_FILE_LOAD, "personality": unix.SYS_PERSONALITY,
	"open_by_handle_at": unix.SYS_OPEN_BY_HANDLE_AT, "reboot": unix.SYS_REBOOT, "swapon": unix.SYS_SWAPON, "swapoff": unix.SYS_SWAPOFF,
	"acct": unix.SYS_ACCT, "syslog": unix.SYS_SYSLOG, "lookup_dcookie": unix.SYS_LOOKUP_DCOOKIE,
	"iopl": unix.SYS_IOPL, "ioperm": unix.SYS_IOPERM, "uselib": unix.SYS_USELIB,
}
