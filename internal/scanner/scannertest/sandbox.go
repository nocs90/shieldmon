package scannertest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/scanner"
)

// probeArg is os.Args[1] when the test binary runs itself inside a sandbox as the
// stand-in for a compromised scanner. It does in Go what a parser exploit would try,
// so the kit needs no shell or network tools inside the sandbox.
const probeArg = "shieldmon-sandbox-probe"

func init() {
	if len(os.Args) > 2 && os.Args[1] == probeArg {
		if err := probe(os.Args[2], os.Args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

// probe performs one operation and returns its error; "read" prints what it read.
// Success alone proves little: a backend may show the process a stand-in for a path
// (bwrap creates the parents of its mounts inside the scratch directory), so the kit
// judges reads by their content and writes by what reaches the host.
func probe(op string, args []string) error {
	switch {
	case op == "read" && len(args) == 1:
		b, err := os.ReadFile(args[0]) //nolint:gosec // G703: probing the sandbox is the point; the kit chooses the target
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(b)
		return err
	case op == "noop" && len(args) == 0:
		return nil
	case op == "userns" && len(args) == 0:
		return probeUserns()
	case op == "personality" && len(args) == 0:
		return probePersonality()
	case op == "list" && len(args) == 1:
		_, err := os.ReadDir(args[0])
		return err
	case op == "write" && len(args) == 1:
		return os.WriteFile(args[0], []byte("x"), 0o600) //nolint:gosec // G703: probing the sandbox is the point; the kit chooses the target
	case op == "write-tmp" && len(args) == 0:
		return os.WriteFile(filepath.Join(os.TempDir(), "probe"), []byte("x"), 0o600) //nolint:gosec // G303: TMPDIR is the process's private scratch directory
	case op == "connect" && len(args) == 1:
		c, err := net.DialTimeout("tcp", args[0], 3*time.Second) //nolint:gosec // G704: probing the sandbox is the point; the kit chooses the target
		if err != nil {
			return err
		}
		return c.Close()
	case op == "hang" && len(args) == 1:
		// A child that outlives its parent is how a compromised scanner would escape the
		// timeout: it must die with the process group.
		self, err := os.Executable()
		if err != nil {
			return err
		}
		child := exec.Command(self, probeArg, "beat", args[0]) //nolint:gosec // G204: the test binary re-running itself as a probe
		if err := child.Start(); err != nil {
			return err
		}
		for {
			time.Sleep(time.Hour)
		}
	case op == "beat" && len(args) == 1:
		for i := 0; ; i++ {
			if err := os.WriteFile(args[0], fmt.Appendf(nil, "%d", i), 0o600); err != nil { //nolint:gosec // G703: probing the sandbox is the point; the kit chooses the target
				return err
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return fmt.Errorf("unknown probe %s %q", op, args)
}

// RequiredSandbox reports whether SHIELDMON_TEST_SANDBOX, a comma-separated list of backend
// names, requires the named backend to run here: tests fail instead of skipping.
func RequiredSandbox(name string) bool {
	return slices.Contains(strings.Split(os.Getenv("SHIELDMON_TEST_SANDBOX"), ","), name)
}

// CheckSandbox runs probes inside the named sandbox backend: a scanner can use its
// declared paths and scratch space, and cannot read or write anything else, write the
// shared DB cache, reach the network while offline, create a user namespace or weaken
// exploit mitigations (the seccomp filter), or outlive its timeout. A backend
// that cannot run on this host is skipped, unless SHIELDMON_TEST_SANDBOX (a comma-separated
// list) names it, in
// which case the test fails (CI sets it where the backend must work).
func CheckSandbox(t *testing.T, name string) {
	t.Helper()
	var backend *scanner.SandboxBackend
	for _, b := range scanner.SandboxBackends() {
		if b.Name == name {
			backend = &b
		}
	}
	if backend == nil {
		t.Fatalf("sandbox backend %q is not registered", name)
	}
	if backend.Description == "" {
		t.Errorf("sandbox backend %q has no description", name)
	}
	if err := backend.Available(); err != nil {
		if RequiredSandbox(name) {
			t.Fatalf("%s: %v", name, err)
		}
		t.Skipf("%s: %v", name, err)
	}
	sb := backend.New()
	if !scanner.Confined(sb) {
		t.Fatalf("sandbox backend %q does not confine scanners", name)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	host := t.TempDir()
	secret, input, out := filepath.Join(host, "secret"), filepath.Join(host, "input"), filepath.Join(host, "out")
	const secretData, inputData = "secret-6f1c", "input-data"
	for f, data := range map[string]string{secret: secretData, input: inputData} {
		if err := os.WriteFile(f, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(out, 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()

	r := scanner.Runner{
		Timeout: time.Minute, Sandbox: sb,
		CacheDir: filepath.Join(host, "cache"), TempDir: filepath.Join(host, "tmp"),
	}
	offline := scanner.WithPolicy(context.Background(), scanner.Policy{ReadOnly: []string{input}, Writable: []string{out}})
	online := scanner.WithPolicy(context.Background(), scanner.Policy{Network: true})
	runOut := func(ctx context.Context, r scanner.Runner, args ...string) (string, error) {
		out, err := r.Run(ctx, self, append([]string{probeArg}, args...)...)
		return string(out), err
	}
	run := func(ctx context.Context, r scanner.Runner, args ...string) error {
		_, err := runOut(ctx, r, args...)
		return err
	}

	allowed := []struct {
		what string
		ctx  context.Context
		args []string
	}{
		{"read a declared input", offline, []string{"read", input}},
		{"write the output directory", offline, []string{"write", filepath.Join(out, "result")}},
		{"write its scratch directory", offline, []string{"write-tmp"}},
		{"write the DB cache while updating", online, []string{"write", filepath.Join(r.CacheDir, "db")}},
		{"connect while updating", online, []string{"connect", addr}},
	}
	for _, c := range allowed {
		if err := run(c.ctx, r, c.args...); err != nil {
			t.Errorf("a sandboxed scanner must be able to %s: %v", c.what, err)
		}
	}
	if got, err := runOut(offline, r, "read", input); err != nil || got != inputData {
		t.Errorf("a sandboxed scanner must read its input as it is: %q %v", got, err)
	}
	if b, err := os.ReadFile(filepath.Join(out, "result")); err != nil || string(b) != "x" {
		t.Errorf("output written in the sandbox must reach the host: %q %v", b, err)
	}

	if got, err := runOut(offline, r, "read", secret); err == nil && got == secretData {
		t.Error("a sandboxed scanner could read outside the policy")
	}
	if err := run(offline, r, "list", os.Getenv("HOME")); err == nil {
		t.Error("a sandboxed scanner could list the home directory")
	}
	if err := run(offline, r, "connect", addr); err == nil {
		t.Error("a sandboxed scanner could connect while offline")
	}
	if err := run(offline, r, "userns"); err == nil {
		t.Error("a sandboxed scanner could create a user namespace")
	}
	if err := run(offline, r, "personality"); err == nil {
		t.Error("a sandboxed scanner could turn off address space randomization")
	}
	// A write may succeed on a stand-in path; it must not reach the host.
	poisoned := filepath.Join(r.CacheDir, "poisoned")
	_ = run(offline, r, "write", input)
	_ = run(offline, r, "write", filepath.Join(host, "new"))
	_ = run(offline, r, "write", poisoned)
	if b, _ := os.ReadFile(input); string(b) != inputData {
		t.Error("a sandboxed scanner could write a read-only input")
	}
	if _, err := os.Stat(filepath.Join(host, "new")); err == nil {
		t.Error("a sandboxed scanner could write outside the policy")
	}
	if _, err := os.Stat(poisoned); err == nil {
		t.Error("a sandboxed scanner could write the DB cache while matching")
	}

	beat := filepath.Join(out, "beat")
	short := r
	short.Timeout = 2 * time.Second
	start := time.Now()
	err = run(offline, short, "hang", beat)
	if err == nil {
		t.Fatal("a hanging scanner must fail with a timeout")
	}
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Errorf("a hanging scanner was stopped after %s (timeout 2s)", elapsed.Round(time.Second))
	}
	before, err := os.ReadFile(beat)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatal("the hanging probe's child never ran")
	}
	time.Sleep(500 * time.Millisecond)
	if after, _ := os.ReadFile(beat); string(after) != string(before) {
		t.Error("a scanner's child process survived the timeout")
	}
}
