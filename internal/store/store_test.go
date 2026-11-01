package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
)

var now = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func seed(t *testing.T) (*Store, int64) {
	t.Helper()
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
	m := model.Match{VulnID: "CVE-1", PURL: "pkg:apk/alpine/zlib@1", PkgKey: "pkg:apk/alpine/zlib", PkgName: "zlib", PkgVersion: "1", Severity: model.SeverityHigh}
	if _, err := s.ReconcileScan(ctx, ReconcileArgs{ScanID: scan, Digest: "sha256:a", TargetIDs: []int64{tg.ID}, Matches: []model.Match{m}, Complete: true, Now: now}); err != nil {
		t.Fatal(err)
	}
	return s, tg.ID
}

func TestAuditTablesAreAppendOnly(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	if err := applyDecision(s, ctx, fs[0].ID, decision(now.AddDate(0, 1, 0)), now); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE finding_events SET reason = 'tampered'`,
		`DELETE FROM finding_events`,
		`DELETE FROM scan_matches`,
		`UPDATE target_digests SET digest = 'sha256:b'`,
		`DELETE FROM decisions`,
	} {
		if _, err := s.db.ExecContext(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: want append-only rejection, got %v", q, err)
		}
	}
}

func TestRecordResolutionTracksLineage(t *testing.T) {
	s, tid := seed(t)
	ctx := context.Background()
	if prev, changed, _ := s.RecordResolution(ctx, tid, "sha256:a", now); changed || prev != "sha256:a" {
		t.Errorf("same digest: prev=%s changed=%t", prev, changed)
	}
	if err := s.UpsertArtifact(ctx, Artifact{Digest: "sha256:b", Repository: "r", MediaType: "m", Platform: "p"}, now); err != nil {
		t.Fatal(err)
	}
	prev, changed, err := s.RecordResolution(ctx, tid, "sha256:b", now)
	if err != nil || !changed || prev != "sha256:a" {
		t.Errorf("new digest: prev=%s changed=%t err=%v", prev, changed, err)
	}
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT count(*) FROM target_digests WHERE target_id = ?`, tid).Scan(&n)
	if n != 2 {
		t.Errorf("target_digests rows = %d, want 2", n)
	}
}

func TestHealthReopenResetsCounters(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	_ = s.RecordHealth(ctx, "db_stale", "grype", "high", "old", now)
	_ = s.RecordHealth(ctx, "db_stale", "grype", "high", "older", now.Add(time.Hour))
	hs, _ := s.ListHealth(ctx, false)
	if len(hs) != 1 || hs[0].Occurrences != 2 || hs[0].Detail != "older" {
		t.Fatalf("health = %+v", hs)
	}
	_ = s.ResolveHealth(ctx, "db_stale", "grype", now.Add(2*time.Hour))
	if hs, _ := s.ListHealth(ctx, false); len(hs) != 0 {
		t.Fatal("resolved finding listed as open")
	}
	_ = s.RecordHealth(ctx, "db_stale", "grype", "high", "again", now.Add(3*time.Hour))
	hs, _ = s.ListHealth(ctx, false)
	if len(hs) != 1 || hs[0].Occurrences != 1 || !hs[0].FirstSeen.Equal(now.Add(3*time.Hour)) {
		t.Fatalf("reopened health = %+v", hs)
	}
}

func TestOpenIsIdempotentAndPrivate(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shieldmon.db")
	for range 2 {
		s, err := Open(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.SchemaVersion(ctx)
		if err != nil || v != 6 {
			t.Fatalf("schema version = %d, %v", v, err)
		}
		s.Close()
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("database mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestDecisionRenewalKeepsState(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	id := fs[0].ID
	dec := func(exp time.Time) error {
		return applyDecision(s, ctx, id, decision(exp), now)
	}
	if err := dec(now.AddDate(0, 1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := dec(now.AddDate(0, 2, 0)); err != nil {
		t.Fatalf("renewal: %v", err)
	}
	ds, _ := s.Decisions(ctx, id)
	if len(ds) != 2 || !ds[0].ExpiresAt.Equal(now.AddDate(0, 2, 0)) {
		t.Fatalf("decisions = %+v", ds)
	}
	if ids, _ := s.ExpireDecisions(ctx, now.AddDate(0, 1, 15)); len(ids) != 0 {
		t.Fatal("the latest decision governs expiry")
	}
	if ids, _ := s.ExpireDecisions(ctx, now.AddDate(0, 2, 1)); len(ids) != 1 {
		t.Fatal("expired decision must reopen the finding")
	}
}

func applyDecision(s *Store, ctx context.Context, id int64, d lifecycle.Decision, now time.Time) error {
	_, err := s.ApplyDecision(ctx, id, d, openPolicy, now)
	return err
}

func TestFixStatePersisted(t *testing.T) {
	s, tid := seed(t)
	ctx := context.Background()
	scan, _ := s.CreateScan(ctx, "sha256:a", tid, "rematch", now)
	m := model.Match{
		VulnID: "CVE-1", PURL: "pkg:apk/alpine/zlib@1", PkgKey: "pkg:apk/alpine/zlib", PkgName: "zlib", PkgVersion: "1",
		Severity: model.SeverityHigh, FixState: model.FixWontFix,
	}
	if _, err := s.ReconcileScan(ctx, ReconcileArgs{ScanID: scan, Digest: "sha256:a", TargetIDs: []int64{tid}, Matches: []model.Match{m}, Complete: true, Now: now}); err != nil {
		t.Fatal(err)
	}
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	if fs[0].FixState != model.FixWontFix {
		t.Fatalf("fix state = %q", fs[0].FixState)
	}
}

func TestDigestPrefixResolution(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	for _, d := range []string{"sha256:abc111", "sha256:abc222"} {
		_ = s.UpsertArtifact(ctx, Artifact{Digest: d, Repository: "r", MediaType: "m", Platform: "p"}, now)
	}
	if ds, _ := s.DigestsWithPrefix(ctx, "abc1"); len(ds) != 1 || ds[0] != "sha256:abc111" {
		t.Errorf("unique prefix: %v", ds)
	}
	if ds, _ := s.DigestsWithPrefix(ctx, "sha256:abc"); len(ds) != 2 {
		t.Errorf("ambiguous prefix must return both: %v", ds)
	}
	if ds, _ := s.DigestsWithPrefix(ctx, "%"); len(ds) != 0 {
		t.Errorf("LIKE wildcards must not match: %v", ds)
	}
}
