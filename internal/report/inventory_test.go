package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/store"
)

// fakeInventory is an InventorySource from fixed data.
type fakeInventory struct {
	targets   []store.Target
	artifacts map[string]store.Artifact
	last      map[string]store.Scan
	complete  map[string]store.Scan
	sboms     map[string][]store.SBOM
	findings  []store.Finding
	history   []store.DigestChange
}

func (f fakeInventory) ListTargets(context.Context) ([]store.Target, error) { return f.targets, nil }

func (f fakeInventory) GetArtifact(_ context.Context, d string) (store.Artifact, error) {
	if a, ok := f.artifacts[d]; ok {
		return a, nil
	}
	return store.Artifact{}, store.ErrNotFound
}

func (f fakeInventory) LatestScan(_ context.Context, d string) (store.Scan, error) {
	if s, ok := f.last[d]; ok {
		return s, nil
	}
	return store.Scan{}, store.ErrNotFound
}

func (f fakeInventory) LatestCompleteScan(_ context.Context, d string) (store.Scan, error) {
	if s, ok := f.complete[d]; ok {
		return s, nil
	}
	return store.Scan{}, store.ErrNotFound
}

func (f fakeInventory) SBOMs(_ context.Context, d string) ([]store.SBOM, error) {
	return f.sboms[d], nil
}

func (f fakeInventory) ListFindings(context.Context, store.FindingFilter) ([]store.Finding, error) {
	return f.findings, nil
}

func (f fakeInventory) DigestHistory(context.Context) ([]store.DigestChange, error) {
	return f.history, nil
}

var invNow = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

func inventoryFixture() fakeInventory {
	const a, b, c = "sha256:aaaa", "sha256:bbbb", "sha256:cccc"
	tools := []model.Tool{{Name: "grype", Version: "0.86.1", DBBuilt: invNow.Add(-12 * time.Hour)}, {Name: "trivy", Version: "0.67.2", DBBuilt: invNow.Add(-20 * time.Hour)}}
	scan := func(d, status string, at time.Time) store.Scan {
		return store.Scan{Digest: d, Kind: "rematch", Status: status, StartedAt: at, Tools: tools}
	}
	sbom := func(d, gen string) store.SBOM {
		return store.SBOM{Digest: d, Generator: gen, GeneratorVersion: "1.0", Format: "cyclonedx-json", SHA256: strings.Repeat(gen[:1], 64), Size: 1234}
	}
	finding := func(d string, sev model.Severity) store.Finding {
		f := store.Finding{Digest: d, State: model.StateOpen}
		f.Severity = sev
		return f
	}
	return fakeInventory{
		targets: []store.Target{
			{ID: 1, Ref: "registry.test/app:prod", Platform: "linux/amd64", CurrentDigest: a, CreatedAt: invNow.AddDate(0, -2, 0), LastResolvedAt: invNow.Add(-time.Hour)},
			{ID: 2, Ref: "registry.test/app:prod", Platform: "linux/arm64", CurrentDigest: b, CreatedAt: invNow.AddDate(0, -2, 0), LastResolvedAt: invNow.Add(-time.Hour)},
			{ID: 3, Ref: "=registry.test/evil|x:1", Platform: "linux/amd64", CurrentDigest: c, CreatedAt: invNow.AddDate(0, 0, -10), LastResolvedAt: invNow.AddDate(0, 0, -5)},
			{ID: 4, Ref: "registry.test/never:1", Platform: "linux/amd64", CreatedAt: invNow.AddDate(0, 0, -1)},
			{ID: 5, Ref: "registry.test/app:latest", Platform: "linux/amd64", CurrentDigest: a, CreatedAt: invNow.AddDate(0, -1, 0), LastResolvedAt: invNow.Add(-time.Hour)},
		},
		artifacts: map[string]store.Artifact{a: {Repository: "registry.test/app"}, b: {Repository: "registry.test/app"}, c: {Repository: "registry.test/evil"}},
		last:      map[string]store.Scan{a: scan(a, store.ScanComplete, invNow.Add(-time.Hour)), b: scan(b, store.ScanPartial, invNow.Add(-time.Hour)), c: scan(c, store.ScanComplete, invNow.AddDate(0, 0, -5))},
		complete:  map[string]store.Scan{a: scan(a, store.ScanComplete, invNow.Add(-time.Hour)), b: scan(b, store.ScanComplete, invNow.AddDate(0, 0, -1)), c: scan(c, store.ScanComplete, invNow.AddDate(0, 0, -5))},
		sboms:     map[string][]store.SBOM{a: {sbom(a, "trivy"), sbom(a, "syft")}, b: {sbom(b, "syft"), sbom(b, "trivy")}, c: {sbom(c, "syft")}},
		findings:  []store.Finding{finding(a, model.SeverityCritical), finding(a, model.SeverityHigh), finding(a, model.SeverityNegligible), finding(b, model.SeverityLow)},
		history: []store.DigestChange{
			{TargetID: 1, Digest: "sha256:old"}, {TargetID: 1, Digest: a, Previous: "sha256:old"}, {TargetID: 2, Digest: b}, {TargetID: 3, Digest: c},
		},
	}
}

func TestInventory(t *testing.T) {
	inv, err := BuildInventory(context.Background(), inventoryFixture(), InventoryOptions{
		Now: invNow, StaleAfter: 36 * time.Hour, Generators: []string{"syft", "trivy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]string{}
	for _, img := range inv.Images {
		gaps[img.Ref+" "+img.Platform] = strings.Join(img.Gaps, ",")
	}
	for image, want := range map[string]string{
		"registry.test/app:prod linux/amd64":   "",
		"registry.test/app:latest linux/amd64": "",
		"registry.test/app:prod linux/arm64":   "last_scan_partial",
		"=registry.test/evil|x:1 linux/amd64":  "stale_evidence,missing_sbom:trivy",
		"registry.test/never:1 linux/amd64":    "unresolved",
	} {
		if gaps[image] != want {
			t.Errorf("%s: gaps %q, want %q", image, gaps[image], want)
		}
	}
	s := inv.Summary
	if s.Targets != 5 || s.Digests != 3 || s.WithGaps != 3 || s.Open["critical"] != 1 || s.Gaps["missing_sbom:trivy"] != 1 {
		t.Errorf("summary %+v: digests shared by two targets count once", s)
	}
	if inv.Images[1].Ref != "registry.test/app:latest" || inv.Images[2].DigestChanges != 1 {
		t.Errorf("sorted by ref and platform, with digest changes: %+v", inv.Images)
	}

	for _, format := range []string{"csv", "md"} {
		var buf bytes.Buffer
		if err := RenderInventory(&buf, inv, format); err != nil {
			t.Fatal(err)
		}
		golden := "testdata/inventory.golden." + format
		if *update {
			if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/report -update)", err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s output differs from %s:\n%s", format, golden, buf.String())
		}
	}
	var buf bytes.Buffer
	if err := RenderInventory(&buf, inv, "csv"); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range recs[1:] {
		for _, v := range rec {
			if v != "" && strings.ContainsRune("=+-@", rune(v[0])) {
				t.Errorf("unsafe cell %q", v)
			}
		}
	}
	if err := RenderInventory(&buf, inv, "xlsx"); err == nil || !strings.Contains(err.Error(), "csv, json, md") {
		t.Errorf("unknown formats name the supported ones: %v", err)
	}
}
