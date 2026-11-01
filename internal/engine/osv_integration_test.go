//go:build integration

package engine_test

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/scanner/scannertest"
	"github.com/nocs90/shieldmon/internal/store"
)

// python:3.12.7-alpine3.20, pinned by digest: Alpine packages and PyPI packages.
const pythonRef = "docker.io/library/python@sha256:5049c050bdc68575a10bcb1885baa0689b6c15152d8a56a7e399fb49f783bf98"

// TestOSVParity matches the same syft SBOMs with grype and osv-scanner and logs how their
// findings overlap per package type: the numbers ADR 0028 records. It runs osv-scanner's
// database download and offline matching in the default sandbox, like the CLI. With
// SHIELDMON_CAPTURE_DIR set it also writes osv-scanner's raw output there, from which the
// unit test fixture is trimmed.
func TestOSVParity(t *testing.T) {
	if _, err := (scanner.Binary{Name: "osv-scanner"}).Resolve(); err != nil {
		// Optional matcher: scripts/install-scanners.sh installs it with SCANNERS=... osv-scanner.
		t.Skipf("osv-scanner not installed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	data := t.TempDir()
	run := scanner.Runner{
		Timeout: 15 * time.Minute, Sandbox: defaultSandbox(t),
		CacheDir: filepath.Join(data, "cache"), TempDir: filepath.Join(data, "tmp"),
		ScratchQuota: 32 << 30,
	}
	osv := &scanner.OSV{Bin: scanner.Binary{Name: "osv-scanner"}, Runner: run, DBAutoUpdate: true, Ecosystems: []string{"Alpine", "PyPI"}}
	grype := &scanner.Grype{Bin: scanner.Binary{Name: "grype"}, Runner: run, DBAutoUpdate: true}
	set := scanner.Set{
		Generators: map[string]scanner.Generator{"syft": &scanner.Syft{Bin: scanner.Binary{Name: "syft"}, Runner: run}},
		Matchers:   []scanner.Matcher{grype, osv},
	}
	p := model.Platform{OS: "linux", Architecture: "amd64"}
	for i, ref := range []string{alpineRef, pythonRef} {
		st, err := store.Open(ctx, ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		eng := &engine.Engine{Store: st, Fetcher: &countingFetcher{}, DataDir: data, Scanners: set}
		if i == 0 {
			if err := eng.UpdateDBs(ctx); err != nil {
				t.Fatal(err)
			}
		}
		r, err := eng.Scan(ctx, ref, p)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != store.ScanComplete {
			t.Fatalf("%s: %+v", ref, r)
		}
		fs, err := st.ListFindings(ctx, store.FindingFilter{})
		if err != nil {
			t.Fatal(err)
		}
		// Both scanners cover Alpine packages, and on the Python image PyPI packages too.
		want := []string{"apk"}
		if ref == pythonRef {
			want = append(want, "pypi")
		}
		logParity(t, ref, fs, want)

		sboms, err := st.SBOMs(ctx, r.Resolved.Digest)
		if err != nil {
			t.Fatal(err)
		}
		sbom := ""
		for _, s := range sboms {
			if s.Generator == "syft" && s.Format == scanner.FormatCycloneDXJSON {
				sbom = filepath.Join(data, s.Path)
			}
		}
		if i == 0 {
			scannertest.CheckMatcher(t, osv, sbom)
		}
		if dir := os.Getenv("SHIELDMON_CAPTURE_DIR"); dir != "" {
			captureOSV(ctx, t, run, sbom, filepath.Join(dir, fmt.Sprintf("osv-%d.json", i)))
		}
	}
}

func logParity(t *testing.T, ref string, fs []store.Finding, shared []string) {
	t.Helper()
	type counts struct{ both, grype, osv int }
	per := map[string]*counts{}
	total := counts{}
	for _, f := range fs {
		typ, _, _ := strings.Cut(strings.TrimPrefix(f.PURL, "pkg:"), "/")
		c := per[typ]
		if c == nil {
			c = &counts{}
			per[typ] = c
		}
		g, o := slices.Contains(f.Scanners, "grype"), slices.Contains(f.Scanners, "osv-scanner")
		for _, x := range []*counts{c, &total} {
			switch {
			case g && o:
				x.both++
			case g:
				x.grype++
			case o:
				x.osv++
			}
		}
	}
	types := make([]string, 0, len(per))
	for k := range per {
		types = append(types, k)
	}
	slices.SortFunc(types, cmp.Compare)
	t.Logf("parity %s: total both=%d grype-only=%d osv-only=%d", ref, total.both, total.grype, total.osv)
	for _, k := range types {
		c := per[k]
		t.Logf("parity %s: %s both=%d grype-only=%d osv-only=%d", ref, k, c.both, c.grype, c.osv)
	}
	for _, typ := range shared {
		if c := per[typ]; c == nil || c.both == 0 {
			t.Errorf("%s: no %s finding confirmed by both grype and osv-scanner: a missing database or a normalization regression", ref, typ)
		}
	}
}

// captureOSV runs osv-scanner as the adapter does and keeps its raw output.
func captureOSV(ctx context.Context, t *testing.T, run scanner.Runner, sbom, out string) {
	t.Helper()
	dir := t.TempDir()
	staged := filepath.Join(dir, "sbom.cdx.json")
	b, err := os.ReadFile(sbom)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staged, b, 0o600); err != nil {
		t.Fatal(err)
	}
	run.ExtraEnv = append(run.ExtraEnv, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+filepath.Join(run.CacheDir, "osv-scanner"))
	run.OKExitCodes = []int{1}
	bin, err := scanner.Binary{Name: "osv-scanner"}.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := run.Run(scanner.WithPolicy(ctx, scanner.Policy{ReadOnly: []string{dir}}), bin,
		"scan", "source", "--offline", "--verbosity", "error", "--format", "json", "-L", staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}
