//go:build linux

package scanner

import (
	"runtime"
	"testing"
)

// TestSeccompTableMatchesKernel checks the hand-written table of the architecture the tests
// run on against golang.org/x/sys/unix, which is generated from the kernel headers.
func TestSeccompTableMatchesKernel(t *testing.T) {
	a, ok := seccompArches[runtime.GOARCH]
	if !ok {
		t.Skip("no filter for", runtime.GOARCH)
	}
	if a.audit != kernelAuditArch {
		t.Errorf("audit arch %#x, kernel %#x", a.audit, kernelAuditArch)
	}
	if len(a.nr) != len(kernelSyscalls) {
		t.Errorf("table has %d syscalls, the cross-check %d", len(a.nr), len(kernelSyscalls))
	}
	for name, want := range kernelSyscalls {
		if got, ok := a.nr[name]; !ok || uintptr(got) != want {
			t.Errorf("%s: table %d (present %t), kernel %d", name, got, ok, want)
		}
	}
}
