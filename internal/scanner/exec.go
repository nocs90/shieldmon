package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/redact"
)

// ErrOutputTooLarge is returned when a scanner writes more than the allowed
// number of bytes to stdout. Scanner output is derived from hostile image
// content and must be bounded.
var ErrOutputTooLarge = errors.New("scanner output exceeds limit")

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
}

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
	// G204 is the point of this function: argv-only exec of a resolved, optionally
	// checksum-pinned scanner binary, never through a shell.
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: see comment above
	cmd.Env = r.env()
	cmd.Stdin = nil
	// On overflow the process tree is killed rather than left blocked on a full pipe.
	stdout := &limitedBuffer{max: maxOut, onOverflow: cancel}
	stderr := &limitedBuffer{max: 64 << 10, truncate: true}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	setProcessGroup(cmd)
	cmd.WaitDelay = 5 * time.Second

	err := cmd.Run()
	if stdout.overflow {
		return nil, fmt.Errorf("%s: %w (%d bytes)", bin, ErrOutputTooLarge, maxOut)
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
