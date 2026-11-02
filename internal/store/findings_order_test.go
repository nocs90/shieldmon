package store

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/nocs90/shieldmon/internal/model"
)

// ListFindings orders, filters and limits in SQL: a limit bounds what is read (the server's
// lists rest on it), and the order is the same as before: most severe, highest CVSS, oldest.
func TestListFindingsOrderAndLimit(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	tg, err := s.UpsertTarget(ctx, "registry.test/app:1", "linux/amd64", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertArtifact(ctx, Artifact{Digest: "sha256:a", Repository: "registry.test/app", MediaType: "m", Platform: "linux/amd64"}, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RecordResolution(ctx, tg.ID, "sha256:a", now); err != nil {
		t.Fatal(err)
	}
	scan, err := s.CreateScan(ctx, "sha256:a", tg.ID, "initial", now)
	if err != nil {
		t.Fatal(err)
	}
	var ms []model.Match
	for i, x := range []struct {
		sev  model.Severity
		cvss float64
	}{
		{model.SeverityLow, 3},
		{model.SeverityCritical, 9.1},
		{model.SeverityHigh, 7.5},
		{model.SeverityCritical, 9.8},
		{model.SeverityUnknown, 0},
		{model.SeverityHigh, 8.1},
		{model.SeverityNegligible, 0},
		{model.SeverityMedium, 5},
	} {
		pkg := fmt.Sprintf("p%d", i)
		ms = append(ms, model.Match{
			VulnID: fmt.Sprintf("CVE-%d", i), PURL: "pkg:apk/alpine/" + pkg + "@1", PkgKey: "pkg:apk/alpine/" + pkg,
			PkgName: pkg, PkgVersion: "1", Severity: x.sev, CVSSScore: x.cvss,
		})
	}
	if _, err := s.ReconcileScan(ctx, ReconcileArgs{ScanID: scan, Digest: "sha256:a", TargetIDs: []int64{tg.ID}, Matches: ms, Complete: true, Now: now}); err != nil {
		t.Fatal(err)
	}
	ids := func(flt FindingFilter) []string {
		t.Helper()
		fs, err := s.ListFindings(ctx, flt)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range fs {
			out = append(out, f.VulnID)
		}
		return out
	}
	all := ids(FindingFilter{})
	if want := []string{"CVE-3", "CVE-1", "CVE-5", "CVE-2", "CVE-7", "CVE-0", "CVE-6", "CVE-4"}; !slices.Equal(all, want) {
		t.Errorf("order = %v, want %v", all, want)
	}
	if got := ids(FindingFilter{Limit: 3}); !slices.Equal(got, all[:3]) {
		t.Errorf("limit 3 = %v", got)
	}
	if got := ids(FindingFilter{MinSeverity: model.SeverityHigh, Limit: 10}); !slices.Equal(got, all[:4]) {
		t.Errorf("high and above = %v", got)
	}
	if got := ids(FindingFilter{MinSeverity: model.SeverityNegligible}); len(got) != 7 {
		t.Errorf("negligible and above leaves out only unknown: %v", got)
	}
}
