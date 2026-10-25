package scanner

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// seccompData is struct seccomp_data with the first argument only.
type seccompData struct {
	nr, arch uint32
	arg0     uint64
}

// runSeccomp evaluates prog like the kernel does, for the instructions seccompFilter emits.
func runSeccomp(t *testing.T, prog []sockFilter, d seccompData) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs:
			switch in.K {
			case seccompNr:
				acc = d.nr
			case seccompAr:
				acc = d.arch
			case seccompA0:
				acc = uint32(d.arg0)
			default:
				t.Fatalf("pc %d: load from offset %d", pc, in.K)
			}
		case bpfJeqK, bpfJsetK:
			taken := acc == in.K
			if in.Code == bpfJsetK {
				taken = acc&in.K != 0
			}
			if taken {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("pc %d: unexpected instruction %#x", pc, in.Code)
		}
	}
	t.Fatal("filter fell off the end without returning")
	return 0
}

func TestSeccompFilter(t *testing.T) {
	for goarch, a := range seccompArches {
		prog, err := seccompFilter(goarch, seccompOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(prog) > 4096 {
			t.Fatalf("%s: %d instructions exceed BPF_MAXINSNS", goarch, len(prog))
		}
		call := func(name string, arg0 uint64) uint32 {
			n, ok := a.nr[name]
			if !ok {
				t.Fatalf("%s: no syscall %s", goarch, name)
			}
			return runSeccomp(t, prog, seccompData{nr: n, arch: a.audit, arg0: arg0})
		}
		for _, name := range seccompDenied {
			if _, ok := a.nr[name]; ok {
				if got := call(name, 0); got != retErrno|errnoEPERM {
					t.Errorf("%s %s: %#x, want EPERM", goarch, name, got)
				}
			}
		}
		// Syscalls a scanner needs, by number: read and write (0 and 1 on amd64, 63 and 64
		// on arm64) and their neighbours, none of which is denied.
		for _, n := range []uint32{0, 1, 63, 64} {
			if got := runSeccomp(t, prog, seccompData{nr: n, arch: a.audit}); got != retAllow {
				t.Errorf("%s syscall %d: %#x, want ALLOW", goarch, n, got)
			}
		}
		const sigchld, cloneVM, cloneThread = 17, 0x100, 0x10000
		for _, flags := range []uint64{sigchld, cloneVM | cloneThread | 0x3d0f00} {
			if got := call("clone", flags); got != retAllow {
				t.Errorf("%s clone(%#x) for a process or thread: %#x, want ALLOW", goarch, flags, got)
			}
		}
		for _, flag := range []uint64{0x10000000, 0x40000000, 0x20000, 0x20000000} { // USER, NET, NS, PID
			if got := call("clone", sigchld|flag); got != retErrno|errnoEPERM {
				t.Errorf("%s clone with namespace flag %#x: %#x, want EPERM", goarch, flag, got)
			}
		}
		if got := call("clone3", 0); got != retErrno|errnoNOSYS {
			t.Errorf("%s clone3: %#x, want ENOSYS so that libc falls back to clone", goarch, got)
		}
		for _, p := range seccompPersonalities {
			if got := call("personality", uint64(p)); got != retAllow {
				t.Errorf("%s personality(%#x): %#x, want ALLOW", goarch, p, got)
			}
		}
		for _, p := range []uint64{0x0040000, 0x0400000, 0x0040008} { // ADDR_NO_RANDOMIZE, READ_IMPLIES_EXEC
			if got := call("personality", p); got != retErrno|errnoEPERM {
				t.Errorf("%s personality(%#x): %#x, want EPERM", goarch, p, got)
			}
		}
		if got := runSeccomp(t, prog, seccompData{nr: 0, arch: 0x40000003}); got != retKill { // AUDIT_ARCH_I386
			t.Errorf("%s: another ABI must kill the process, got %#x", goarch, got)
		}
		if a.x32 {
			if got := runSeccomp(t, prog, seccompData{nr: x32Bit, arch: a.audit}); got != retKill { // read in the x32 ABI
				t.Errorf("%s: an x32 syscall must kill the process, got %#x", goarch, got)
			}
		}
	}
	if _, err := seccompFilter("riscv64", seccompOptions{}); err == nil {
		t.Error("an architecture without a table must be refused")
	}
}

func TestSeccompOptions(t *testing.T) {
	for goarch, a := range seccompArches {
		for _, c := range []struct {
			o                  seccompOptions
			socket, truncation bool // denied
		}{
			{seccompOptions{}, false, false},
			{seccompOptions{offline: true}, true, false},
			{seccompOptions{denyTruncate: true}, false, true},
		} {
			prog, err := seccompFilter(goarch, c.o)
			if err != nil {
				t.Fatal(err)
			}
			for name, deny := range map[string]bool{"socket": c.socket, "truncate": c.truncation} {
				want := uint32(retAllow)
				if deny {
					want = retErrno | errnoEPERM
				}
				if got := runSeccomp(t, prog, seccompData{nr: a.nr[name], arch: a.audit}); got != want {
					t.Errorf("%s %+v %s: %#x, want %#x", goarch, c.o, name, got, want)
				}
			}
			if got := runSeccomp(t, prog, seccompData{nr: a.nr["bpf"], arch: a.audit}); got != retErrno|errnoEPERM {
				t.Errorf("%s %+v: options must not drop the base deny-list", goarch, c.o)
			}
		}
	}
}

func TestSeccompProgramEncoding(t *testing.T) {
	if _, ok := seccompArches[runtime.GOARCH]; !ok {
		t.Skip("no filter for", runtime.GOARCH)
	}
	b, err := seccompProgram(runtime.GOARCH, seccompOptions{})
	if err != nil {
		t.Fatal(err)
	}
	prog, _ := seccompFilter(runtime.GOARCH, seccompOptions{})
	if len(b) != 8*len(prog) {
		t.Fatalf("%d bytes for %d instructions: struct sock_filter is 8 bytes", len(b), len(prog))
	}
	var first sockFilter
	if err := binary.Read(bytes.NewReader(b[:8]), binary.NativeEndian, &first); err != nil || first != prog[0] {
		t.Fatalf("first instruction decodes to %+v, want %+v (%v)", first, prog[0], err)
	}
}
