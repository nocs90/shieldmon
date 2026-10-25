//go:build !(linux || darwin)

package scanner

import (
	"errors"
	"io/fs"
)

func diskFree(string) (uint64, error) {
	return 0, errors.New("free disk space unknown on this platform")
}

func allocated(fi fs.FileInfo) int64 { return fi.Size() }

// InspectMount describes the filesystem dir is on.
func InspectMount(string) (Mount, error) {
	return Mount{}, errors.New("filesystem details unknown on this platform")
}
