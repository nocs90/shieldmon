package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrNoSandbox is returned when no sandbox backend can confine scanners on this host.
var ErrNoSandbox = errors.New("no scanner sandbox available")

// Policy is what one scanner process may touch (docs/adr/0011-scanner-sandbox.md).
// Backends translate it; adapters never see it.
type Policy struct {
	// ReadOnly are inputs: the OCI layout or SBOM being processed.
	ReadOnly []string
	// Writable are directories the process writes its results to.
	Writable []string
	// Scratch is the process's private temporary directory, seen as /tmp when confined.
	// Runner fills it in.
	Scratch string
	// Network is granted only to vulnerability DB updates, never to a process that
	// reads image content or SBOMs.
	Network bool
}

type policyKey struct{}

// WithPolicy attaches the policy for scanner processes started with ctx.
func WithPolicy(ctx context.Context, p Policy) context.Context {
	return context.WithValue(ctx, policyKey{}, p)
}

// PolicyFrom returns the policy attached to ctx: by default no inputs, no writable
// directories and no network.
func PolicyFrom(ctx context.Context) Policy {
	p, _ := ctx.Value(policyKey{}).(Policy)
	return p
}

// Launch is how to start one confined process.
type Launch struct {
	Argv []string
	// Files are passed to the process as file descriptors 3, 4, ... in order, each read
	// from its start (bwrap reads its seccomp filter from one).
	Files [][]byte
}

// Sandbox confines scanner processes.
type Sandbox interface {
	// Command returns how to run bin with args confined by p.
	Command(p Policy, bin string, args []string) (Launch, error)
}

// SandboxBackend describes a sandbox implementation. Backends register themselves from
// an init function, like scanner plugins.
type SandboxBackend struct {
	// Name is the value of scanners.sandbox.backend that selects this backend.
	Name        string
	Description string
	// Auto orders the backends tried by "auto", lowest first; 0 excludes the backend.
	Auto int
	// Available returns nil when the backend can confine processes on this host, or
	// why it cannot.
	Available func() error
	New       func() Sandbox
}

// AutoSandbox selects the first available backend in Auto order.
const AutoSandbox = "auto"

var sandboxes = map[string]SandboxBackend{}

// RegisterSandbox makes a sandbox backend available. It panics on duplicate or invalid
// registrations, which are programming errors.
func RegisterSandbox(b SandboxBackend) {
	mu.Lock()
	defer mu.Unlock()
	if b.Name == "" || b.Name == AutoSandbox || b.Available == nil || b.New == nil {
		panic("scanner: RegisterSandbox requires Name, Available and New")
	}
	if _, dup := sandboxes[b.Name]; dup {
		panic("scanner: duplicate sandbox " + b.Name)
	}
	sandboxes[b.Name] = b
}

// SandboxBackends returns all registered backends sorted by name.
func SandboxBackends() []SandboxBackend {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]SandboxBackend, 0, len(sandboxes))
	for _, b := range sandboxes {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SelectSandbox resolves scanners.sandbox.backend. An unknown name is an error. A
// backend that cannot run here is not: the returned Sandbox refuses every command with
// the reason, so that commands which never start a scanner keep working.
func SelectSandbox(name string) (string, Sandbox, error) {
	if name == "" || name == AutoSandbox {
		b, err := selectAuto(SandboxBackends())
		if err != nil {
			return AutoSandbox, refusing{err}, nil
		}
		return b.Name, b.New(), nil
	}
	for _, b := range SandboxBackends() {
		if b.Name != name {
			continue
		}
		if err := b.Available(); err != nil {
			return name, refusing{fmt.Errorf("%w: %s: %w", ErrNoSandbox, name, err)}, nil
		}
		return name, b.New(), nil
	}
	var names []string
	for _, b := range SandboxBackends() {
		names = append(names, b.Name)
	}
	return "", nil, fmt.Errorf("scanners.sandbox.backend: unknown backend %q (known: %s, %s)", name, AutoSandbox, strings.Join(names, ", "))
}

func selectAuto(all []SandboxBackend) (SandboxBackend, error) {
	var candidates []SandboxBackend
	for _, b := range all {
		if b.Auto > 0 {
			candidates = append(candidates, b)
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].Auto < candidates[j].Auto })
	var reasons []string
	for _, b := range candidates {
		err := b.Available()
		if err == nil {
			return b, nil
		}
		reasons = append(reasons, b.Name+": "+err.Error())
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no backend supports this platform")
	}
	return SandboxBackend{}, fmt.Errorf("%w (%s); set scanners.sandbox.backend: none to run scanners unsandboxed",
		ErrNoSandbox, strings.Join(reasons, "; "))
}

// Confined reports whether sb keeps scanners away from the host's files and network. Only
// the explicit opt-out (and no sandbox at all) does not; a backend that cannot run here
// counts as confined because it refuses to start scanners.
func Confined(sb Sandbox) bool {
	_, none := sb.(unconfined)
	return sb != nil && !none
}

// refusing stands in for a backend that cannot run, so the failure surfaces when a scan
// starts a scanner rather than when the configuration loads.
type refusing struct{ err error }

func (r refusing) Command(Policy, string, []string) (Launch, error) { return Launch{}, r.err }

// unconfined runs scanners as ordinary child processes: the explicit opt-out.
type unconfined struct{}

func (unconfined) Command(_ Policy, bin string, args []string) (Launch, error) {
	return Launch{Argv: append([]string{bin}, args...)}, nil
}

func init() {
	RegisterSandbox(SandboxBackend{
		Name:        "none",
		Description: "no confinement: scanners run with the invoking user's filesystem and network",
		Available:   func() error { return nil },
		New:         func() Sandbox { return unconfined{} },
	})
}
