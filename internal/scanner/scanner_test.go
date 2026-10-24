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
