package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseGrype(t *testing.T) {
	res, err := ParseGrype(readFixture(t, "grype-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Tool.Name != "grype" || res.Tool.Version != "0.119.0" || res.Tool.DBVersion != "v6.1.10" {
		t.Errorf("tool = %+v", res.Tool)
	}
	if res.Tool.DBBuilt.IsZero() {
		t.Error("DB build time not parsed")
	}
	if len(res.Matches) != 12 {
		t.Fatalf("matches = %d, want 12", len(res.Matches))
	}
	var bb *model.RawMatch
	for i := range res.Matches {
		if res.Matches[i].PkgName == "busybox" {
			bb = &res.Matches[i]
		}
	}
	if bb == nil {
		t.Fatal("busybox match missing")
	}
	if bb.VulnID != "CVE-2022-48174" || bb.Severity != model.SeverityCritical || bb.CVSSScore != 9.8 {
		t.Errorf("busybox = %+v", bb)
	}
	if len(bb.FixVersions) == 0 || bb.FixVersions[0] != "1.36.1-r1" {
		t.Errorf("fix versions = %v", bb.FixVersions)
	}
	if !strings.HasPrefix(bb.PURL, "pkg:apk/alpine/busybox@") {
		t.Errorf("purl = %s", bb.PURL)
	}
}

func TestParseTrivy(t *testing.T) {
	res, err := ParseTrivy(readFixture(t, "trivy-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 12 {
		t.Fatalf("matches = %d, want 12", len(res.Matches))
	}
	m := res.Matches[0]
	if m.Scanner != "trivy" || m.VulnID == "" || m.PURL == "" || m.Severity == model.SeverityUnknown {
		t.Errorf("first match = %+v", m)
	}
}

func TestParseTrivyVersion(t *testing.T) {
	tool, err := parseTrivyVersion([]byte(`{"Version":"0.74.0","VulnerabilityDB":{"Version":2,"UpdatedAt":"2026-10-19T19:08:34.442427859Z"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if tool.Version != "0.74.0" || tool.DBVersion != "v2" || tool.DBBuilt.Year() != 2026 {
		t.Errorf("tool = %+v", tool)
	}
}

// TestRealOutputsDeduplicate checks normalization on real grype and trivy
// output for the same image: overlapping CVEs must merge into one match.
func TestRealOutputsDeduplicate(t *testing.T) {
	g, err := ParseGrype(readFixture(t, "grype-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	tr, err := ParseTrivy(readFixture(t, "trivy-alpine-3.18.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	merged := normalize.Merge(append(g.Matches, tr.Matches...))
	both := 0
	for _, m := range merged {
		if len(m.Scanners) == 2 {
			both++
		}
	}
	// 7 (package, CVE) pairs are reported by both scanners in the fixtures.
	if both != 7 {
		t.Errorf("matches confirmed by both scanners = %d, want 7", both)
	}
	if len(merged) != 24-both {
		t.Errorf("merged = %d, want %d", len(merged), 24-both)
	}
}

func TestRunnerBoundsOutput(t *testing.T) {
	r := Runner{Timeout: 10 * time.Second, MaxOutput: 1024}
	// Finite output over the limit must fail, not be silently truncated.
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", "yes shieldmon | head -c 5000"); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("finite overflow: want ErrOutputTooLarge, got %v", err)
	}
	// Unbounded output must kill the process promptly, not wait for the timeout.
	start := time.Now()
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", "yes shieldmon"); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("unbounded output: want ErrOutputTooLarge, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("overflow took %s: process was not killed on overflow", time.Since(start))
	}
	out, err := r.Run(context.Background(), "/bin/sh", "-c", "printf ok")
	if err != nil || string(out) != "ok" {
		t.Fatalf("output under the limit: %q, %v", out, err)
	}
}

func TestRunnerTimeout(t *testing.T) {
	r := Runner{Timeout: 200 * time.Millisecond}
	start := time.Now()
	_, err := r.Run(context.Background(), "/bin/sh", "-c", "sleep 30")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("process tree was not killed promptly")
	}
}

func TestRunnerDoesNotLeakCredentials(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "super-secret")
	t.Setenv("GITLAB_TOKEN", "glpat-xxxxxxxxxxxxxxxxxxxx")
	t.Setenv("DOCKER_CONFIG", "/home/user/.docker")
	t.Setenv("GRYPE_DB_CACHE_DIR", "/cache/grype")
	// Scanner-prefixed registry credentials: trivy would send these to its DB registry.
	t.Setenv("TRIVY_PASSWORD", "registry-secret")
	t.Setenv("TRIVY_REGISTRY_TOKEN", "registry-token")
	t.Setenv("GRYPE_REGISTRY_AUTH_TOKEN", "registry-token")
	t.Setenv("SYFT_REGISTRY_AUTH_USERNAME", "robot")
	out, err := Runner{}.Run(context.Background(), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	env := string(out)
	leaks := []string{
		"AWS_SECRET_ACCESS_KEY", "GITLAB_TOKEN", "DOCKER_CONFIG",
		"TRIVY_PASSWORD", "TRIVY_REGISTRY_TOKEN", "GRYPE_REGISTRY_AUTH_TOKEN", "SYFT_REGISTRY_AUTH_USERNAME",
	}
	for _, leaked := range leaks {
		if strings.Contains(env, leaked) {
			t.Errorf("%s leaked into scanner environment", leaked)
		}
	}
	if !strings.Contains(env, "GRYPE_DB_CACHE_DIR=/cache/grype") {
		t.Error("scanner-specific configuration must pass through")
	}
}

func TestRunnerRedactsStderr(t *testing.T) {
	_, err := Runner{}.Run(context.Background(), "/bin/sh", "-c", "echo 'password=hunter2 failed' >&2; exit 3")
	if err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("secret leaked in error: %v", err)
	}
}

func TestBinaryChecksumPin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fake-scanner")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (Binary{Name: "fake", Path: p, SHA256: sum}).Resolve(); err != nil {
		t.Errorf("matching pin rejected: %v", err)
	}
	_, err = Binary{Name: "fake", Path: p, SHA256: strings.Repeat("0", 64)}.Resolve()
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("want ErrChecksumMismatch, got %v", err)
	}
}

func TestRequiredGenerators(t *testing.T) {
	syft, trivy := &Syft{}, &Trivy{}
	s := Set{Generators: map[string]Generator{"syft": syft, "trivy": trivy}, Matchers: []Matcher{&Grype{}, trivy}}
	gens, err := s.RequiredGenerators()
	if err != nil || len(gens) != 2 {
		t.Fatalf("gens = %v, err = %v", gens, err)
	}
	s.Generators = map[string]Generator{"trivy": trivy}
	if _, err := s.RequiredGenerators(); err == nil {
		t.Error("grype without syft must be a configuration error")
	}
}

// fakeScanner writes a script that logs its arguments and grype's auto-update setting,
// one line per run, and prints an empty JSON document.
func fakeScanner(t *testing.T) (Binary, func() []string) {
	t.Helper()
	dir := t.TempDir()
	log, bin := filepath.Join(dir, "log"), filepath.Join(dir, "scanner")
	script := "#!/bin/sh\n{ printf '%s ' \"$@\"; printf '| GRYPE_DB_AUTO_UPDATE=%s\\n' \"$GRYPE_DB_AUTO_UPDATE\"; } >> " + log + "\necho '{}'\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return Binary{Name: "fake", Path: bin}, func() []string {
		b, _ := os.ReadFile(log)
		_ = os.Remove(log)
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

func TestMatchersNeverUpdateWhileScanning(t *testing.T) {
	bin, runs := fakeScanner(t)
	ctx := context.Background()
	for _, confined := range []bool{false, true} {
		var r Runner
		if confined {
			r.Sandbox = &passSandbox{}
		}
		g := &Grype{Bin: bin, Runner: r, DBAutoUpdate: true}
		if _, err := g.Match(ctx, "/data/x.json"); err != nil {
			t.Fatal(err)
		}
		if got := runs(); len(got) != 1 || !strings.HasSuffix(got[0], "| GRYPE_DB_AUTO_UPDATE=false") {
			t.Errorf("grype must not update its DB while matching: %q", got)
		}

		tr := &Trivy{Bin: bin, Runner: r}
		if _, err := tr.Generate(ctx, Source{OCIDir: "/data/oci"}, t.TempDir()); err != nil {
			t.Fatal(err)
		}
		if _, err := tr.Match(ctx, "/data/x.json"); err != nil {
			t.Fatal(err)
		}
		got := runs()
		if len(got) != 3 { // generate, match, version
			t.Fatalf("trivy runs = %q", got)
		}
		for _, run := range got[:2] {
			if !strings.Contains(run, "--skip-db-update --skip-java-db-update") {
				t.Errorf("trivy must not update its DBs while scanning: %q", run)
			}
		}
		if strings.Contains(got[0], "--offline-scan") != confined {
			t.Errorf("confined=%t: trivy cataloging must be offline exactly when confined: %q", confined, got[0])
		}
	}
}

func TestMatchersUpdateDBUnlessManagedOutOfBand(t *testing.T) {
	bin, runs := fakeScanner(t)
	ctx := context.Background()
	if err := (&Grype{Bin: bin, DBAutoUpdate: true}).UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	if got := runs(); len(got) != 1 || !strings.HasPrefix(got[0], "db update ") {
		t.Errorf("grype update runs = %q", got)
	}
	if err := (&Trivy{Bin: bin}).UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	got := runs()
	if len(got) != 2 || !strings.HasPrefix(got[0], "image --download-db-only ") || !strings.HasPrefix(got[1], "image --download-java-db-only ") {
		t.Errorf("trivy update runs = %q", got)
	}

	if err := (&Grype{Bin: bin}).UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (&Trivy{Bin: bin, SkipDBUpdate: true}).UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	if got := runs(); len(got) != 1 || got[0] != "" {
		t.Errorf("DBs managed out of band must not be updated: %q", got)
	}
}

func TestRunnerEnforcesScratchQuota(t *testing.T) {
	r := Runner{Timeout: time.Minute, TempDir: t.TempDir(), ScratchQuota: 4 << 20}
	// A decompression bomb: keeps unpacking into TMPDIR, 1 MiB at a time.
	bomb := `i=0; while :; do head -c 1048576 /dev/zero > "$TMPDIR/f$i"; i=$((i+1)); sleep 0.01; done`
	start := time.Now()
	_, err := r.Run(context.Background(), "/bin/sh", "-c", bomb)
	if !errors.Is(err, ErrScratchQuota) {
		t.Fatalf("want ErrScratchQuota, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the quota was enforced after %s", time.Since(start))
	}

	// Many empty files are bounded too: they cost inodes and measuring time, not bytes.
	old := scratchMaxEntries
	scratchMaxEntries = 50
	t.Cleanup(func() { scratchMaxEntries = old })
	files := `i=0; while :; do : > "$TMPDIR/e$i"; i=$((i+1)); done`
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", files); !errors.Is(err, ErrScratchQuota) {
		t.Fatalf("too many entries: want ErrScratchQuota, got %v", err)
	}

	if out, err := r.Run(context.Background(), "/bin/sh", "-c", `head -c 1024 /dev/zero > "$TMPDIR/small" && printf ok`); err != nil || string(out) != "ok" {
		t.Fatalf("a process within its quota must run: %q %v", out, err)
	}
}

func TestRunnerEnforcesFreeDiskFloor(t *testing.T) {
	if _, err := diskFree(t.TempDir()); err != nil {
		t.Skip("free disk space unknown here:", err)
	}
	r := Runner{Timeout: time.Minute, TempDir: t.TempDir(), MinFreeBytes: 1 << 62}
	start := time.Now()
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", "sleep 30"); !errors.Is(err, ErrDiskSpace) {
		t.Fatalf("want ErrDiskSpace, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("the floor was enforced after %s", time.Since(start))
	}
}

func TestScratchUsageCountsAllocatedSpace(t *testing.T) {
	dir := t.TempDir()
	// A sparse file: its size is huge, the disk space it uses is not.
	f, err := os.Create(filepath.Join(dir, "sparse"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(1 << 40); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if used, _, over := scratchUsage(dir, 1<<30); over {
		t.Errorf("a sparse 1 TiB file counted as %d bytes", used)
	}
	if err := os.WriteFile(filepath.Join(dir, "real"), make([]byte, 64<<10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, entries, over := scratchUsage(dir, 32<<10); !over || entries < 2 {
		t.Errorf("64 KiB of data must exceed a 32 KiB quota (entries %d)", entries)
	}
}

func TestRunnerBoundsFilesOfOfflineProcesses(t *testing.T) {
	sb := &passSandbox{}
	r := Runner{Sandbox: sb, ScratchQuota: 1 << 20}
	if _, err := r.Run(WithPolicy(context.Background(), Policy{}), "/bin/sh", "-c", "true"); err != nil {
		t.Fatal(err)
	}
	if sb.got.MaxFileBytes != 1<<20 {
		t.Errorf("an offline process must get the quota as its file size limit: %+v", sb.got)
	}
	if _, err := r.Run(WithPolicy(context.Background(), Policy{Network: true}), "/bin/sh", "-c", "true"); err != nil {
		t.Fatal(err)
	}
	if sb.got.MaxFileBytes != 0 {
		t.Errorf("a DB update writes DBs bigger than the quota: %+v", sb.got)
	}
}

func TestRunnerNamesTheFileSizeLimit(t *testing.T) {
	r := Runner{Timeout: time.Minute, TempDir: t.TempDir(), ScratchQuota: 1 << 20}
	// What RLIMIT_FSIZE leaves behind: a file stopped exactly at the limit, and a scanner
	// that exits with a bare status because Go ignores SIGXFSZ.
	_, err := r.Run(context.Background(), "/bin/sh", "-c", `head -c 1048576 /dev/zero > "$TMPDIR/var-bomb"; exit 1`)
	if !errors.Is(err, ErrFileSize) || !strings.Contains(err.Error(), `"var-bomb"`) {
		t.Fatalf("want ErrFileSize naming the file, got %v", err)
	}
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", `head -c 1024 /dev/zero > "$TMPDIR/small"; exit 1`); err == nil || errors.Is(err, ErrFileSize) {
		t.Fatalf("a failure with every file under the limit is the scanner's own: %v", err)
	}
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", `head -c 1048576 /dev/zero > "$TMPDIR/exact"`); err != nil {
		t.Fatalf("a scanner that succeeds is not reported: %v", err)
	}
	// syft deletes its truncated file before exiting; what is left is its error message.
	efbig := `printf 'ERROR unable to populate layer cache: write /tmp/stereoscope/partial: file too large\n' >&2; exit 1`
	if _, err := r.Run(context.Background(), "/bin/sh", "-c", efbig); !errors.Is(err, ErrFileSize) {
		t.Fatalf("a scanner reporting EFBIG under a file size limit: want ErrFileSize, got %v", err)
	}
	if _, err := (Runner{Timeout: time.Minute}).Run(context.Background(), "/bin/sh", "-c", efbig); errors.Is(err, ErrFileSize) {
		t.Fatalf("without a file size limit, EFBIG is the scanner's own failure: %v", err)
	}
}

func TestScannersReportTheirErrors(t *testing.T) {
	bin, runs := fakeScanner(t)
	ctx := context.Background()
	if _, err := (&Syft{Bin: bin}).Generate(ctx, Source{OCIDir: "/data/oci"}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Grype{Bin: bin, DBAutoUpdate: true}).Match(ctx, "/data/x.json"); err != nil {
		t.Fatal(err)
	}
	if err := (&Grype{Bin: bin, DBAutoUpdate: true}).UpdateDB(ctx); err != nil {
		t.Fatal(err)
	}
	for _, run := range runs() {
		// --quiet silences syft's and grype's errors too: a failure would say only "exit status 1".
		if strings.Contains(run, "--quiet") {
			t.Errorf("scanner run with --quiet: %q", run)
		}
	}
}
