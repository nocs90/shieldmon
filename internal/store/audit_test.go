package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tamper runs SQL as an attacker with the database file would: without the append-only
// triggers of the tables it touches.
func tamper(t *testing.T, s *Store, tables []string, stmts ...string) {
	t.Helper()
	ctx := context.Background()
	exec := func(q string) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`PRAGMA foreign_keys = OFF`)
	for _, tbl := range tables {
		exec(`DROP TRIGGER IF EXISTS ` + tbl + `_no_update`)
		exec(`DROP TRIGGER IF EXISTS ` + tbl + `_no_delete`)
	}
	for _, q := range stmts {
		exec(q)
	}
}

func kinds(r AuditReport) string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, p.Kind+":"+p.Table)
	}
	return strings.Join(out, ",")
}

func sealedStore(t *testing.T) *Store {
	t.Helper()
	s, _ := seed(t)
	ctx := context.Background()
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	if err := applyDecision(s, ctx, fs[0].ID, decision(now.AddDate(0, 1, 0)), now); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAuditChainVerifies(t *testing.T) {
	s := sealedStore(t)
	ctx := context.Background()
	r, err := s.VerifyAudit(ctx, nil)
	if err != nil || !r.OK() || r.Entries < 5 || len(r.Pending) != 0 {
		t.Fatalf("an untouched store verifies, everything sealed: %+v %v", r, err)
	}
	head, err := s.AuditHead(ctx)
	if err != nil || head.Seq != r.Entries || len(head.Hash) != 64 || head.Format != DigestFormat {
		t.Fatalf("head %+v %v", head, err)
	}
	// An SBOM is written outside a transaction: pending until the next write seals it.
	if err := s.InsertSBOM(ctx, SBOM{Digest: "sha256:a", Generator: "syft", Format: "cyclonedx-json", SHA256: "00", Path: "x", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.VerifyAudit(ctx, nil); !r.OK() || r.Pending["sboms"] != 1 {
		t.Errorf("unsealed new rows are pending, not problems: %+v", r)
	}
	if err := s.SealAudit(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.VerifyAudit(ctx, []AuditDigest{head}); !r.OK() || len(r.Pending) != 0 || r.Digests != 1 {
		t.Errorf("sealed, and the earlier digest is still in the chain: %+v", r)
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	for what, c := range map[string]struct {
		tables []string
		stmts  []string
		want   string
	}{
		"decision edited": {[]string{"decisions"}, []string{`UPDATE decisions SET author = 'someone else'`}, "row_changed:decisions"},
		"event deleted":   {[]string{"finding_events"}, []string{`DELETE FROM finding_events WHERE id = (SELECT max(id) FROM finding_events)`}, "row_missing:finding_events"},
		"evidence edited": {[]string{"scan_matches"}, []string{`UPDATE scan_matches SET severity = 'negligible'`}, "row_changed:scan_matches"},
		"match replaced": {[]string{"scan_matches"}, []string{
			`DELETE FROM scan_matches WHERE rowid = 1`,
			`INSERT INTO scan_matches (rowid, scan_id, finding_id, scanners, severity) VALUES (1, 999, 999, '["grype"]', 'low')`,
		}, "row_missing:scan_matches,row_inserted:scan_matches"},
		"link edited":   {[]string{"audit_chain"}, []string{`UPDATE audit_chain SET row_hash = '00' WHERE seq = 2`}, "broken_link:"},
		"entry deleted": {[]string{"audit_chain"}, []string{`DELETE FROM audit_chain WHERE seq = 2`}, "broken_link:"},
	} {
		t.Run(what, func(t *testing.T) {
			s := sealedStore(t)
			tamper(t, s, c.tables, c.stmts...)
			r, err := s.VerifyAudit(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.OK() || !strings.Contains(kinds(r), c.want) {
				t.Errorf("got %q, want %q", kinds(r), c.want)
			}
		})
	}
}

// TestAuditChainRewriteNeedsADigest: whoever rewrites rows and rebuilds the whole chain
// passes a verification against itself; an exported digest catches it.
func TestAuditChainRewriteNeedsADigest(t *testing.T) {
	s := sealedStore(t)
	ctx := context.Background()
	exported, err := s.AuditHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tamper(t, s, []string{"decisions", "audit_chain"},
		`UPDATE decisions SET justification = 'rewritten after the fact, quietly'`,
		`DELETE FROM audit_chain`)
	if err := s.tx(ctx, func(tx *sql.Tx) error { return nil }); err != nil { // reseals everything
		t.Fatal(err)
	}
	if r, _ := s.VerifyAudit(ctx, nil); !r.OK() {
		t.Fatalf("a consistent rewrite verifies against itself: %q", kinds(r))
	}
	r, err := s.VerifyAudit(ctx, []AuditDigest{exported})
	if err != nil || r.OK() || !strings.Contains(kinds(r), AuditDigestDiffer) {
		t.Errorf("the exported digest no longer matches: %q %v", kinds(r), err)
	}
	ahead := exported
	ahead.Seq += 1000
	if r, _ := s.VerifyAudit(ctx, []AuditDigest{ahead}); !strings.Contains(kinds(r), AuditDigestAhead) {
		t.Errorf("a digest beyond the head means a truncated chain: %q", kinds(r))
	}
}

func TestCanonicalEncodingIsInjective(t *testing.T) {
	a, _ := rowHash("t", []string{"c"}, []any{"\xff"})
	b, _ := rowHash("t", []string{"c"}, []any{"\xfe"})
	c, _ := rowHash("t", []string{"c"}, []any{int64(5)})
	d, _ := rowHash("t", []string{"c"}, []any{"5"})
	e, _ := rowHash("u", []string{"c"}, []any{"5"})
	if a == b || c == d || d == e {
		t.Error("distinct bytes, types or tables must hash differently")
	}
}

func TestScanSealedWhenFinished(t *testing.T) {
	s, tid := seed(t)
	ctx := context.Background()
	older, err := s.CreateScan(ctx, "sha256:a", tid, "rematch", now)
	if err != nil {
		t.Fatal(err)
	}
	newer, err := s.CreateScan(ctx, "sha256:a", tid, "rematch", now)
	if err != nil {
		t.Fatal(err)
	}
	// The newer scan finishes first and moves the high-water mark past the older one.
	if err := s.FinishScan(ctx, newer, ScanComplete, nil, "", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := s.FinishScan(ctx, older, ScanFailed, nil, "boom", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	r, err := s.VerifyAudit(ctx, nil)
	if err != nil || !r.OK() || r.Pending["scans"] != 0 {
		t.Fatalf("both scans sealed as they finished: %q %+v %v", kinds(r), r.Pending, err)
	}
	tamper(t, s, nil, `UPDATE scans SET status = 'complete' WHERE id = `+strconv.FormatInt(older, 10))
	if r, _ := s.VerifyAudit(ctx, nil); !strings.Contains(kinds(r), "row_changed:scans") {
		t.Errorf("a failed scan turned complete: %q", kinds(r))
	}
}
