package scanner

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

// diskFree returns the bytes an unprivileged process may still write on path's filesystem.
func diskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	if st.Bsize <= 0 {
		return 0, errors.New("statfs: invalid block size")
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// mountOf returns the size and options of path's filesystem.
func mountOf(path string) (Mount, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return Mount{}, err
	}
	if st.Bsize <= 0 {
		return Mount{}, errors.New("statfs: invalid block size")
	}
	return Mount{
		Size:   st.Blocks * uint64(st.Bsize),
		NoExec: st.Flags&unix.ST_NOEXEC != 0,
		NoSuid: st.Flags&unix.ST_NOSUID != 0,
		NoDev:  st.Flags&unix.ST_NODEV != 0,
	}, nil
}
