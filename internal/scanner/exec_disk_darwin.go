package scanner

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// diskFree returns the bytes an unprivileged process may still write on path's filesystem.
func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// mountOf returns the size and options of path's filesystem.
func mountOf(path string) (Mount, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Mount{}, err
	}
	return Mount{
		Size:   st.Blocks * uint64(st.Bsize),
		NoExec: st.Flags&unix.MNT_NOEXEC != 0,
		NoSuid: st.Flags&unix.MNT_NOSUID != 0,
		NoDev:  st.Flags&unix.MNT_NODEV != 0,
	}, nil
}
