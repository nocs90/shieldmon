package scanner

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeInfo is the subset of fs.FileInfo the bwrap backend inspects.
type fakeInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (f fakeInfo) Mode() fs.FileMode { return f.mode }
func (f fakeInfo) IsDir() bool       { return f.mode.IsDir() }

// mergedUsr is a Debian/Ubuntu layout: /bin and /lib are symlinks into /usr.
func mergedUsr() *bwrap {
	entries := map[string]fs.FileMode{"/usr": fs.ModeDir, "/bin": fs.ModeSymlink, "/lib": fs.ModeSymlink, "/lib64": fs.ModeDir}
	links := map[string]string{"/bin": "usr/bin", "/lib": "usr/lib"}
	return &bwrap{
		path:   "/usr/bin/bwrap",
		goarch: "amd64",
		lstat: func(p string) (fs.FileInfo, error) {
			m, ok := entries[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return fakeInfo{mode: m}, nil
		},
		link: func(p string) (string, error) { return links[p], nil },
	}
}

// hasArgs reports whether flag occurs in argv followed by want.
func hasArgs(argv []string, flag string, want ...string) bool {
	for i, a := range argv {
		if a == flag && i+len(want) < len(argv) && slices.Equal(argv[i+1:i+1+len(want)], want) {
			return true
		}
	}
	return false
}

func TestBwrapCommandConfinesToPolicy(t *testing.T) {
	p := Policy{
		ReadOnly: []string{"/data/sboms/x.json", "/data/cache"},
		Writable: []string{"/data/tmp/scan-1/syft"},
		Scratch:  "/data/tmp/proc-1",
	}
	l, err := mergedUsr().Command(p, "/opt/scanners/grype", []string{"sbom:/data/sboms/x.json", "-o", "json"})
	if err != nil {
		t.Fatal(err)
	}
	argv := l.Argv
	offline, _ := seccompProgram("amd64", seccompOptions{offline: true})
	if !hasArgs(argv, "--seccomp", "3") || len(l.Files) != 1 || !bytes.Equal(l.Files[0], offline) {
		t.Errorf("the offline seccomp filter must be passed as fd 3: %q", argv)
	}
	sep := slices.Index(argv, "--")
	if sep < 0 || !slices.Equal(argv[sep+1:], []string{"/opt/scanners/grype", "sbom:/data/sboms/x.json", "-o", "json"}) {
		t.Fatalf("scanner argv must follow --: %q", argv)
	}
	opts := argv[:sep]
	for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session"} {
		if !slices.Contains(opts, flag) {
			t.Errorf("missing %s", flag)
		}
	}
	if slices.Contains(opts, "--share-net") || slices.Contains(opts, "/etc/resolv.conf") {
		t.Error("an offline policy must not share the network namespace or resolver config")
	}
	if slices.Contains(opts, "--tmpfs") {
		t.Error("a process with a scratch directory must not get an in-memory /tmp")
	}
	checks := []struct {
		flag string
		args []string
	}{
		{"--cap-drop", []string{"ALL"}},
		{"--ro-bind", []string{"/usr", "/usr"}},
		{"--symlink", []string{"usr/bin", "/bin"}},
		{"--symlink", []string{"usr/lib", "/lib"}},
		{"--ro-bind", []string{"/lib64", "/lib64"}},
		{"--ro-bind", []string{"/opt/scanners/grype", "/opt/scanners/grype"}},
		{"--ro-bind", []string{"/data/sboms/x.json", "/data/sboms/x.json"}},
		{"--ro-bind", []string{"/data/cache", "/data/cache"}},
		{"--bind", []string{"/data/tmp/scan-1/syft", "/data/tmp/scan-1/syft"}},
		{"--bind", []string{"/data/tmp/proc-1", "/tmp"}},
		{"--setenv", []string{"HOME", "/tmp"}},
		{"--setenv", []string{"TMPDIR", "/tmp"}},
	}
	for _, c := range checks {
		if !hasArgs(opts, c.flag, c.args...) {
			t.Errorf("missing %s %q in %q", c.flag, c.args, opts)
		}
	}
	for _, hidden := range []string{"/", "/home", "/root", "/data"} {
		for _, flag := range []string{"--ro-bind", "--ro-bind-try", "--bind"} {
			if hasArgs(opts, flag, hidden, hidden) {
				t.Errorf("%s must not be visible to the scanner", hidden)
			}
		}
	}
}

func TestBwrapCommandNetworkAndOrdering(t *testing.T) {
	p := Policy{
		Network:  true,
		ReadOnly: []string{"/data/cache/grype/db", "/data/cache"},
		Writable: []string{"/data/cache"},
	}
	l, err := mergedUsr().Command(p, "/usr/bin/grype", []string{"db", "update"})
	if err != nil {
		t.Fatal(err)
	}
	argv := l.Argv
	online, _ := seccompProgram("amd64", seccompOptions{})
	if len(l.Files) != 1 || !bytes.Equal(l.Files[0], online) {
		t.Error("a process with network must get the filter that allows sockets")
	}
	if !slices.Contains(argv, "--share-net") || !hasArgs(argv, "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf") {
		t.Errorf("a network policy needs the network namespace and resolver config: %q", argv)
	}
	if hasArgs(argv, "--ro-bind", "/usr/bin/grype", "/usr/bin/grype") {
		t.Error("binaries under /usr are already visible and must not be bound again")
	}
	if !hasArgs(argv, "--bind", "/data/cache", "/data/cache") || hasArgs(argv, "--ro-bind", "/data/cache", "/data/cache") {
		t.Error("a path that is both read-only and writable must be writable")
	}
	parent, child := slices.Index(argv, "/data/cache"), slices.Index(argv, "/data/cache/grype/db")
	if parent < 0 || child < parent {
		t.Error("parent directories must be mounted before nested ones")
	}
	if !hasArgs(argv, "--size", "67108864", "--tmpfs", "/tmp") {
		t.Error("without a scratch directory /tmp must be a bounded tmpfs")
	}
}

func TestBwrapCommandRejectsUnsafePolicy(t *testing.T) {
	for _, p := range []Policy{{Writable: []string{"/"}}, {ReadOnly: []string{""}}, {Scratch: "/"}} {
		if _, err := mergedUsr().Command(p, "/usr/bin/grype", nil); err == nil {
			t.Errorf("policy %+v must be refused", p)
		}
	}
	noFilter := mergedUsr()
	noFilter.goarch = "riscv64"
	if _, err := noFilter.Command(Policy{}, "/usr/bin/grype", nil); err == nil {
		t.Error("bwrap must refuse to run a scanner without the seccomp filter")
	}
}

// passSandbox records the policy and runs the command unconfined.
type passSandbox struct{ got Policy }

func (s *passSandbox) Command(p Policy, bin string, args []string) (Launch, error) {
	s.got = p
	return Launch{Argv: append([]string{bin}, args...)}, nil
}

func TestRunnerGivesEachProcessScratchAndCache(t *testing.T) {
	data := t.TempDir()
	sb := &passSandbox{}
	r := Runner{Sandbox: sb, CacheDir: filepath.Join(data, "cache"), TempDir: filepath.Join(data, "tmp")}
	out, err := r.Run(WithPolicy(context.Background(), Policy{ReadOnly: []string{"/in"}}), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sb.got.ReadOnly, []string{"/in", r.CacheDir}) || len(sb.got.Writable) != 0 {
		t.Errorf("an offline process must see the cache read-only: %+v", sb.got)
	}
	if !strings.HasPrefix(sb.got.Scratch, r.TempDir+string(os.PathSeparator)) {
		t.Errorf("scratch %q not under %q", sb.got.Scratch, r.TempDir)
	}
	if _, err := os.Stat(sb.got.Scratch); !os.IsNotExist(err) {
		t.Errorf("the scratch directory must be removed when the process exits: %v", err)
	}
	for _, want := range []string{"XDG_CACHE_HOME=" + r.CacheDir, "TMPDIR=" + sb.got.Scratch} {
		if !strings.Contains(string(out), want) {
			t.Errorf("environment lacks %s", want)
		}
	}

	if _, err := r.Run(WithPolicy(context.Background(), Policy{Network: true}), "/bin/sh", "-c", "true"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sb.got.Writable, []string{r.CacheDir}) {
		t.Errorf("a DB update must be able to write the cache: %+v", sb.got)
	}
}

// TestBwrapSandbox checks, with real bubblewrap, what only its namespaces provide; the
// properties every backend shares are probed by scannertest.CheckSandbox. CI sets
// SHIELDMON_TEST_SANDBOX=bwrap so that a runner that cannot start it fails the build
// instead of skipping.
func TestBwrapSandbox(t *testing.T) {
	if err := bwrapAvailable(); err != nil {
		if slices.Contains(strings.Split(os.Getenv("SHIELDMON_TEST_SANDBOX"), ","), "bwrap") {
			t.Fatal("bwrap:", err)
		}
		t.Skip("bwrap:", err)
	}
	path, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	input, out := filepath.Join(host, "input"), filepath.Join(host, "out")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := newBwrap(path)
	if err != nil {
		t.Fatal(err)
	}
	r := Runner{Timeout: time.Minute, Sandbox: b, TempDir: filepath.Join(host, "tmp")}
	ctx := WithPolicy(context.Background(), Policy{ReadOnly: []string{input}, Writable: []string{out}})
	sh := func(script string) error {
		_, err := r.Run(ctx, "/bin/sh", "-c", script)
		return err
	}
	if err := sh("cat " + input + " && echo ok > " + out + "/result && echo x > /tmp/x"); err != nil {
		t.Fatalf("declared paths and scratch must be usable: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "result")); err != nil || string(b) != "ok\n" {
		t.Fatalf("output written in the sandbox is missing: %q %v", b, err)
	}
	denied := map[string]string{
		"see a network device":     "grep -v -e lo: -e Inter -e face /proc/net/dev | grep -q :",
		"see the host's processes": "test $(ls -d /proc/[0-9]* | wc -l) -gt 10",
		"inherit the host's HOME":  `test "$HOME" != /tmp`,
	}
	for what, script := range denied {
		if err := sh(script); err == nil {
			t.Errorf("a sandboxed scanner could %s", what)
		}
	}
}

func TestBwrapStartErrorNamesAppArmorFix(t *testing.T) {
	dir := t.TempDir()
	probe := errors.New("bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted")
	for _, c := range []struct {
		value string // "" leaves the setting absent (older kernels, other distros)
		hint  bool
	}{{"1\n", true}, {"0\n", false}, {"", false}} {
		sysctl := filepath.Join(dir, "absent")
		if c.value != "" {
			sysctl = filepath.Join(dir, strings.TrimSpace(c.value))
			if err := os.WriteFile(sysctl, []byte(c.value), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		msg := bwrapStartError(probe, sysctl).Error()
		if !strings.Contains(msg, "RTM_NEWADDR") {
			t.Errorf("the probe's error is lost: %q", msg)
		}
		if got := strings.Contains(msg, "deploy/apparmor/shieldmon-bwrap"); got != c.hint {
			t.Errorf("sysctl %q: AppArmor hint = %t, want %t: %q", c.value, got, c.hint, msg)
		}
	}
}
