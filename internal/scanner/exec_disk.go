//go:build linux || darwin

package scanner

import (
	"io/fs"
	"path/filepath"
	"syscall"
)

// InspectMount describes the filesystem dir is on.
func InspectMount(dir string) (Mount, error) {
	m, err := mountOf(dir)
	if err != nil {
		return Mount{}, err
	}
	var st, parent syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		return Mount{}, err
	}
	if err := syscall.Stat(filepath.Dir(dir), &parent); err != nil {
		return Mount{}, err
	}
	m.Dedicated = st.Dev != parent.Dev
	return m, nil
}

// allocated is the disk space a file uses, which for a sparse file is less than its size.
func allocated(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}
