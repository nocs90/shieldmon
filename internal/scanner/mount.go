package scanner

// Mount describes the filesystem a directory is on. A dedicated, size-limited filesystem
// mounted noexec,nosuid,nodev at the Runner's TempDir is the kernel-enforced bound on what
// scanners write, and W^X for all of it (docs/adr/0011-scanner-sandbox.md, deploy/scratch).
type Mount struct {
	// Dedicated is true when the directory is a mount point: not on its parent's filesystem.
	Dedicated             bool
	Size                  uint64 // bytes
	NoExec, NoSuid, NoDev bool
}
