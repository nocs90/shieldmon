//go:build integration

package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// alpine:3.18.0 linux/amd64, pinned by digest: an old image with many known CVEs.
const alpineRef = "docker.io/library/alpine@sha256:c0669ef34cdc14332c0f1ab0c2c01acb91d96014b172f1a76f3a39e63d1f0bda"

type countingFetcher struct {
	engine.RegistryFetcher
	fetches int
}

func (c *countingFetcher) Fetch(ctx context.Context, r oci.Resolved, dir string) error {
	c.fetches++
	return c.RegistryFetcher.Fetch(ctx, r, dir)
}

// TestRealScanners runs syft, grype and trivy end to end. It needs network
// access and the three binaries in PATH: make test-integration.
func TestRealScanners(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	run := scanner.Runner{Timeout: 15 * time.Minute}
	trivy := &scanner.Trivy{Bin: scanner.Binary{Name: "trivy"}, Runner: run}
	fetcher := &countingFetcher{}
	eng := &engine.Engine{
		Store:   st,
		Fetcher: fetcher,
		DataDir: t.TempDir(),
		Scanners: scanner.Set{
			Generators: map[string]scanner.Generator{"syft": &scanner.Syft{Bin: scanner.Binary{Name: "syft"}, Runner: run}, "trivy": trivy},
			Matchers:   []scanner.Matcher{&scanner.Grype{Bin: scanner.Binary{Name: "grype"}, Runner: run, DBAutoUpdate: true}, trivy},
		},
	}
	p := model.Platform{OS: "linux", Architecture: "amd64"}

	// Matchers never download DBs while matching; the separate step does.
	if err := eng.UpdateDBs(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := eng.Scan(ctx, alpineRef, p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != store.ScanComplete || r.Kind != "initial" || len(r.SBOMsCreated) != 2 {
		t.Fatalf("first scan: %+v", r)
	}
	if r.Matches < 20 {
		t.Errorf("only %d matches on alpine 3.18.0", r.Matches)
	}
	fs, err := st.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	both := 0
	for _, f := range fs {
		if len(f.Scanners) == 2 {
			both++
		}
	}
	if both == 0 {
		t.Error("no finding confirmed by both scanners: normalization regression")
	}
	for _, tool := range r.Tools {
		if tool.Version == "" || tool.DBBuilt.IsZero() {
			t.Errorf("tool metadata incomplete: %+v", tool)
		}
	}

	r2, err := eng.Scan(ctx, alpineRef, p)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Kind != "rematch" || r2.Created != 0 || fetcher.fetches != 1 {
		t.Fatalf("second scan must be an SBOM rematch without pulling: %+v fetches=%d", r2, fetcher.fetches)
	}
}
