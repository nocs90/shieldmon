//go:build linux || darwin

package scanner

import (
	"runtime"
	"testing"
)

func TestInspectMount(t *testing.T) {
	m, err := InspectMount(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if m.Dedicated || m.Size == 0 {
		t.Errorf("a test's temporary directory is a plain directory on a sized filesystem: %+v", m)
	}
	if runtime.GOOS != "linux" {
		return
	}
	// /proc is its own mount, and distributions mount it noexec,nosuid,nodev.
	if m, err := InspectMount("/proc"); err != nil || !m.Dedicated || !m.NoExec || !m.NoSuid || !m.NoDev {
		t.Errorf("/proc: %+v %v", m, err)
	}
}
