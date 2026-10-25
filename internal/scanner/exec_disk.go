//go:build linux || darwin

package scanner

import (
	"io/fs"
	"syscall"
)

// allocated is the disk space a file uses, which for a sparse file is less than its size.
func allocated(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}
