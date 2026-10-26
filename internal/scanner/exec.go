package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nocs90/shieldmon/internal/redact"
)

// ErrOutputTooLarge is returned when a scanner writes more than the allowed
// number of bytes to stdout. Scanner output is derived from hostile image
// content and must be bounded.
var ErrOutputTooLarge = errors.New("scanner output exceeds limit")

// ErrScratchQuota is returned when a scanner's scratch directory outgrows
// Runner.ScratchQuota: image content can unpack to far more than it downloads.
var ErrScratchQuota = errors.New("scanner exceeded its scratch space quota")

// ErrDiskSpace is returned when free space under Runner.TempDir drops below
// Runner.MinFreeBytes while a scanner runs, wherever it writes.
var ErrDiskSpace = errors.New("free disk space below the configured floor")

// ErrFileSize is returned when a scanner fails after the kernel refused to let one of its
// files grow past Policy.MaxFileBytes (RLIMIT_FSIZE). Go scanners ignore SIGXFSZ and see
// only EFBIG, so without this the failure is a bare exit status.
var ErrFileSize = errors.New("scanner hit its file size limit")

// ErrChecksumMismatch is returned when a pinned scanner binary does not
// match its expected SHA-256.
var ErrChecksumMismatch = errors.New("scanner binary checksum mismatch")

// Binary is a scanner executable, optionally pinned by SHA-256.
type Binary struct {
	Name   string // logical name, e.g. "grype"
	Path   string // explicit path; looked up in PATH when empty
	SHA256 string // expected hex digest; empty disables pinning
}

// Resolve finds the binary and verifies its checksum when pinned.
func (b Binary) Resolve() (string, error) {
	p := b.Path
	if p == "" {
		var err error
		if p, err = exec.LookPath(b.Name); err != nil {
			return "", fmt.Errorf("%s: not found in PATH: %w", b.Name, err)
		}
	}
	if b.SHA256 == "" {
		return p, nil
	}
	got, err := FileSHA256(p)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(got, b.SHA256) {
		return "", fmt.Errorf("%w: %s at %s has sha256 %s, expected %s", ErrChecksumMismatch, b.Name, p, got, b.SHA256)
	}
	return p, nil
}

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// envAllowlist is the set of environment variables passed through to
// scanners. Registry credentials are deliberately absent: ShieldMon fetches
// images itself and hands scanners a local OCI layout.
var envAllowlist = []string{
	"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "XDG_CACHE_HOME",
}

// envPrefixAllowlist passes through scanner-specific configuration.
var envPrefixAllowlist = []string{"GRYPE_", "SYFT_", "TRIVY_"}

// credentialEnvMarkers keep credentials out of the prefixed variables (TRIVY_PASSWORD,
// GRYPE_REGISTRY_AUTH_TOKEN, ...). Scanners only read local layouts and SBOMs, and trivy
// presents --username/--password to every registry it contacts, including its
// vulnerability DB repository.
var credentialEnvMarkers = []string{"AUTH", "CREDENTIAL", "HEADER", "KEY", "PASSWORD", "SECRET", "TOKEN", "USERNAME"}

// Runner executes scanner processes with bounded time and output.
type Runner struct {
	Timeout   time.Duration
	MaxOutput int64
	// ExtraEnv is appended after the allowlisted environment.
	ExtraEnv []string
	// Sandbox confines every process to the Policy attached to its context. Nil runs
	// processes unconfined; the CLI always sets one (scanners.sandbox.backend).
	Sandbox Sandbox
	// CacheDir holds the scanners' vulnerability DBs and caches (XDG_CACHE_HOME). Processes
	// without network see it read-only, so that a compromised parser cannot poison the DB
	// that later scans trust.
	CacheDir string
	// TempDir is where every process gets a private scratch directory (TMPDIR), removed
	// when it exits. Empty leaves TMPDIR alone.
	TempDir string
	// ScratchQuota bounds the disk space and entries of a process's scratch directory
	// (0: unbounded); a backend that can also bounds each file the process writes.
	// Exceeding it kills the process tree with ErrScratchQuota.
	ScratchQuota int64
	// MinFreeBytes kills the process tree with ErrDiskSpace when free space on
	// TempDir's filesystem drops below it (0: no floor).
	MinFreeBytes int64
}

// watchInterval is how often a running process's disk use is checked; between two checks
// it can write at most this long at the disk's speed.
var watchInterval = 100 * time.Millisecond

// scratchMaxEntries bounds the files and directories in a scratch directory, so that
// neither the inode table nor the walk that measures the directory can be exhausted.
var scratchMaxEntries = 1 << 20

// Confined reports whether processes started by r run in a sandbox (see Confined).
func (r Runner) Confined() bool { return Confined(r.Sandbox) }

func (r Runner) env() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		ok := false
		for _, a := range envAllowlist {
			if k == a {
				ok = true
				break
			}
		}
		for _, p := range envPrefixAllowlist {
			if strings.HasPrefix(k, p) && !isCredentialVar(k) {
				ok = true
				break
			}
		}
		if ok {
			out = append(out, kv)
		}
	}
	return append(out, r.ExtraEnv...)
}

func isCredentialVar(k string) bool {
	k = strings.ToUpper(k)
	for _, m := range credentialEnvMarkers {
		if strings.Contains(k, m) {
			return true
		}
	}
	return false
}

// prepare adds the cache and a fresh scratch directory to the policy and environment of
// one process. cleanup removes the scratch directory.
func (r Runner) prepare(p Policy) (Policy, []string, func(), error) {
	env := r.env()
	cleanup := func() {}
	if r.CacheDir != "" {
		if err := os.MkdirAll(r.CacheDir, 0o700); err != nil {
			return p, nil, cleanup, err
		}
		env = append(env, "XDG_CACHE_HOME="+r.CacheDir)
		if p.Network {
			p.Writable = append(slices.Clone(p.Writable), r.CacheDir)
		} else {
			p.ReadOnly = append(slices.Clone(p.ReadOnly), r.CacheDir)
		}
	}
	if r.TempDir != "" {
		if err := os.MkdirAll(r.TempDir, 0o700); err != nil {
			return p, nil, cleanup, err
		}
		scratch, err := os.MkdirTemp(r.TempDir, "proc-")
		if err != nil {
			return p, nil, cleanup, err
		}
		cleanup = func() { _ = os.RemoveAll(scratch) }
		p.Scratch = scratch
		env = append(env, "TMPDIR="+scratch)
	}
	if r.ScratchQuota > 0 && !p.Network {
		// No single file can be larger than the quota. DB updates write DBs bigger than a
		// small quota into the cache, and never read image content.
		p.MaxFileBytes = r.ScratchQuota
	}
	return p, env, cleanup, nil
}

// watch enforces ScratchQuota and MinFreeBytes while a process runs: on a breach it cancels
// the process (killing its group) and stop returns why.
func (r Runner) watch(scratch string, cancel context.CancelFunc) (stop func() error) {
	quota := r.ScratchQuota > 0 && scratch != ""
	floor := r.MinFreeBytes > 0 && r.TempDir != ""
	if !quota && !floor {
		return func() error { return nil }
	}
	done := make(chan struct{})
	var reason error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(watchInterval)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			if floor {
				if floorBytes := r.MinFreeBytes; floorBytes > 0 {
					if free, err := diskFree(r.TempDir); err == nil && free < uint64(floorBytes) {
						reason = fmt.Errorf("%w: %d bytes free, floor %d", ErrDiskSpace, free, floorBytes)
					}
				}
			}
			if quota && reason == nil {
				if used, entries, over := scratchUsage(scratch, r.ScratchQuota); over {
					reason = fmt.Errorf("%w: %d bytes in %d entries (quota %d bytes, %d entries)",
						ErrScratchQuota, used, entries, r.ScratchQuota, scratchMaxEntries)
				}
			}
			if reason != nil {
				cancel()
				return
			}
		}
	}()
	return func() error {
		close(done)
		wg.Wait()
		return reason
	}
}

// fileSizeBreach tells a process stopped by RLIMIT_FSIZE from other failures: either a file
// is left at the limit, or the process reported EFBIG ("file too large"). Scanners may
// delete the truncated file before exiting, so the first alone is not enough.
func fileSizeBreach(p Policy, stderr []byte) error {
	if name, ok := fileAtLimit(p.MaxFileBytes, append([]string{p.Scratch}, p.Writable...)...); ok {
		return fmt.Errorf("%w: %s reached %d bytes", ErrFileSize, name, p.MaxFileBytes)
	}
	if bytes.Contains(bytes.ToLower(stderr), []byte("file too large")) {
		return fmt.Errorf("%w: a write past %d bytes was refused (EFBIG)", ErrFileSize, p.MaxFileBytes)
	}
	return nil
}

// fileAtLimit looks under dirs for a regular file of at least limit bytes: one the kernel
// stopped at RLIMIT_FSIZE. The name comes from image content, so it is quoted and shortened.
func fileAtLimit(limit int64, dirs ...string) (string, bool) {
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		found, entries := "", 0
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entries++; entries > scratchMaxEntries {
				return fs.SkipAll
			}
			if d.Type().IsRegular() {
				if fi, err := d.Info(); err == nil && fi.Size() >= limit {
					found = path
					return fs.SkipAll
				}
			}
			return nil
		})
		if found != "" {
			rel, err := filepath.Rel(dir, found)
			if err != nil {
				rel = filepath.Base(found)
			}
			if len(rel) > 200 {
				rel = rel[:200] + "…"
			}
			return strconv.Quote(rel), true
		}
	}
	return "", false
}

// scratchUsage measures dir, stopping as soon as it exceeds quota bytes or scratchMaxEntries.
// Symlinks are not followed; entries that vanish while walking are skipped.
func scratchUsage(dir string, quota int64) (used int64, entries int, over bool) {
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		entries++
		if fi, err := d.Info(); err == nil {
			used += allocated(fi)
		}
		if used > quota || entries > scratchMaxEntries {
			over = true
			return fs.SkipAll
		}
		return nil
	})
	return used, entries, over
}

// Run executes bin with args (never through a shell) and returns stdout.
func (r Runner) Run(ctx context.Context, bin string, args ...string) ([]byte, error) {
	var cancel context.CancelFunc
	if r.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	maxOut := r.MaxOutput
	if maxOut <= 0 {
		maxOut = 512 << 20
	}
	p, env, cleanup, err := r.prepare(PolicyFrom(ctx))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", bin, err)
	}
	defer cleanup()
	argv := append([]string{bin}, args...)
	if r.Sandbox != nil {
		if argv, err = r.Sandbox.Command(p, bin, args); err != nil {
			return nil, fmt.Errorf("%s: %w", bin, err)
		}
	}
	// G204 is the point of this function: argv-only exec of a resolved, optionally
	// checksum-pinned scanner binary (or its sandbox launcher), never through a shell.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: see comment above
	cmd.Env = env
	cmd.Stdin = nil
	// On overflow the process tree is killed rather than left blocked on a full pipe.
	stdout := &limitedBuffer{max: maxOut, onOverflow: cancel}
	stderr := &limitedBuffer{max: 64 << 10, truncate: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	setProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second

	stop := r.watch(p.Scratch, cancel)
	err = cmd.Run()
	breach := stop()
	if stdout.overflow {
		return nil, fmt.Errorf("%s: %w (%d bytes)", bin, ErrOutputTooLarge, maxOut)
	}
	if err != nil && breach == nil && p.MaxFileBytes > 0 {
		breach = fileSizeBreach(p, stderr.buf.Bytes())
	}
	if breach != nil {
		return nil, fmt.Errorf("%s: %w", bin, breach)
	}
	if err != nil {
		if ctx.Err() != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("%s: timed out after %s", bin, r.Timeout)
			}
			return nil, fmt.Errorf("%s: %w", bin, ctx.Err())
		}
		msg := redact.String(strings.TrimSpace(stderr.buf.String()))
		if len(msg) > 2000 {
			msg = msg[len(msg)-2000:]
		}
		name := bin
		if len(args) > 0 {
			name += " " + args[0]
		}
		return nil, fmt.Errorf("%s: %w: %s", name, err, msg)
	}
	return stdout.buf.Bytes(), nil
}

// limitedBuffer stops accepting writes past max bytes. The buffer is a named
// field, not embedded: embedding would promote bytes.Buffer.ReadFrom, which
// io.Copy (used by os/exec) prefers over Write, silently bypassing the limit.
type limitedBuffer struct {
	buf        bytes.Buffer
	max        int64
	truncate   bool // silently drop overflow instead of failing the write
	overflow   bool
	onOverflow func()
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	room := b.max - int64(b.buf.Len())
	if int64(len(p)) <= room {
		return b.buf.Write(p)
	}
	if room > 0 {
		b.buf.Write(p[:room])
	}
	if b.truncate {
		return len(p), nil
	}
	if !b.overflow && b.onOverflow != nil {
		b.onOverflow()
	}
	b.overflow = true
	return int(max(room, 0)), ErrOutputTooLarge
}
