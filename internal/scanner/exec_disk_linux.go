package scanner

import (
	"errors"
	"syscall"
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
