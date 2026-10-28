package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Problem kinds found by VerifyAudit.
const (
	AuditBrokenLink   = "broken_link"    // an entry's hash or sequence does not follow from the previous one
	AuditRowChanged   = "row_changed"    // the row differs from what was sealed
	AuditRowMissing   = "row_missing"    // a sealed row is gone
	AuditRowInserted  = "row_inserted"   // rows below the sealed high-water mark that were never sealed
	AuditDigestDiffer = "digest_differs" // an exported digest's entry has another hash: the chain was rewritten
	AuditDigestAhead  = "digest_ahead"   // an exported digest is beyond the head: the chain was truncated
	AuditUnknownTable = "unknown_table"  // an entry names a table that is not audited
)

// maxReportedProblems bounds the problems listed (all are counted).
const maxReportedProblems = 100

// AuditProblem is one verification failure.
type AuditProblem struct {
	Kind   string `json:"kind"`
	Seq    int64  `json:"seq,omitempty"`
	Table  string `json:"table,omitempty"`
	Key    string `json:"key,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// AuditReport is the outcome of VerifyAudit.
type AuditReport struct {
	Head     AuditDigest      `json:"head"`
	Entries  int64            `json:"entries"`
	Digests  int              `json:"digests_checked"`
	Pending  map[string]int64 `json:"pending,omitempty"` // rows written but not sealed yet
	Problems []AuditProblem   `json:"problems"`
	// Count is the number of problems, of which at most maxReportedProblems are listed.
	Count int `json:"problem_count"`
}

// OK reports whether the chain verified.
func (r AuditReport) OK() bool { return r.Count == 0 }

func (r *AuditReport) problem(p AuditProblem) {
	r.Count++
	if len(r.Problems) < maxReportedProblems {
		r.Problems = append(r.Problems, p)
	}
}

type chainEntry struct {
	seq     int64
	tbl     string
	key     string
	rowID   int64
	cols    int
	rowHash string
	hash    string
}

// VerifyAudit recomputes every link and every sealed row, looks for rows inserted below the
// sealed high-water marks, and checks that each given digest (exported earlier) is still in
// the chain. It reads only.
func (s *Store) VerifyAudit(ctx context.Context, digests []AuditDigest) (AuditReport, error) {
	r := AuditReport{Problems: []AuditProblem{}, Pending: map[string]int64{}}
	head, err := s.AuditHead(ctx)
	if err != nil {
		return r, err
	}
	r.Head = head
	sealed := map[string]int64{}
	missing := map[string]int64{}
	hw := map[string]int64{}
	prev, next := genesis, int64(1)
	for {
		batch, err := s.chainBatch(ctx, next)
		if err != nil {
			return r, err
		}
		for _, e := range batch {
			if e.seq != next || linkHash(prev, e.seq, e.tbl, e.key, e.cols, e.rowHash) != e.hash {
				r.problem(AuditProblem{Kind: AuditBrokenLink, Seq: e.seq, Table: e.tbl, Key: e.key})
			}
			prev, next = e.hash, e.seq+1
			sealed[e.tbl]++
			hw[e.tbl] = max(hw[e.tbl], e.rowID)
		}
		if err := s.verifyRows(ctx, batch, &r, missing); err != nil {
			return r, err
		}
		r.Entries += int64(len(batch))
		if len(batch) < sealBatch {
			break
		}
	}
	for _, t := range auditTables {
		where := "rowid <= ?"
		if t.where != "" {
			where = t.where + " AND " + where
		}
		var below, above int64
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+t.name+` WHERE `+where, hw[t.name]).Scan(&below); err != nil {
			return r, err
		}
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM `+t.name+` WHERE `+strings.Replace(where, "<=", ">", 1), hw[t.name]).Scan(&above); err != nil {
			return r, err
		}
		if extra := below - (sealed[t.name] - missing[t.name]); extra > 0 {
			r.problem(AuditProblem{Kind: AuditRowInserted, Table: t.name, Detail: fmt.Sprintf("%d row(s) below the sealed mark were never sealed", extra)})
		}
		if above > 0 {
			r.Pending[t.name] = above
		}
	}
	for _, d := range digests {
		r.Digests++
		if d.Seq > head.Seq {
			r.problem(AuditProblem{Kind: AuditDigestAhead, Seq: d.Seq, Detail: fmt.Sprintf("the chain ends at %d", head.Seq)})
			continue
		}
		var h string
		err := s.db.QueryRowContext(ctx, `SELECT hash FROM audit_chain WHERE seq = ?`, d.Seq).Scan(&h)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && h != d.Hash) {
			r.problem(AuditProblem{Kind: AuditDigestDiffer, Seq: d.Seq})
			continue
		}
		if err != nil {
			return r, err
		}
	}
	return r, nil
}

func (s *Store) chainBatch(ctx context.Context, from int64) ([]chainEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT seq, tbl, row_key, row_id, cols, row_hash, hash FROM audit_chain
		WHERE seq >= ? ORDER BY seq LIMIT ?`, from, sealBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []chainEntry
	for rows.Next() {
		var e chainEntry
		if err := rows.Scan(&e.seq, &e.tbl, &e.key, &e.rowID, &e.cols, &e.rowHash, &e.hash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// verifyRows reads the rows of a batch of entries, per table and column-set version, and
// compares their hashes.
func (s *Store) verifyRows(ctx context.Context, batch []chainEntry, r *AuditReport, missing map[string]int64) error {
	type group struct {
		tbl  string
		cols int
	}
	groups := map[group][]chainEntry{}
	var order []group
	for _, e := range batch {
		g := group{e.tbl, e.cols}
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], e)
	}
	for _, g := range order {
		entries := groups[g]
		t, ok := auditTableNamed(g.tbl)
		if !ok || g.cols < 1 || g.cols > t.version() {
			for _, e := range entries {
				r.problem(AuditProblem{Kind: AuditUnknownTable, Seq: e.seq, Table: e.tbl, Key: e.key})
			}
			continue
		}
		cols := t.cols[g.cols-1]
		found, err := s.rowsByKey(ctx, t, cols, entries)
		if err != nil {
			return err
		}
		for _, e := range entries {
			vals, ok := found[e.key]
			if !ok {
				missing[t.name]++
				r.problem(AuditProblem{Kind: AuditRowMissing, Seq: e.seq, Table: t.name, Key: e.key})
				continue
			}
			h, err := rowHash(t.name, cols, vals)
			if err != nil {
				return err
			}
			if h != e.rowHash {
				r.problem(AuditProblem{Kind: AuditRowChanged, Seq: e.seq, Table: t.name, Key: e.key})
			}
		}
	}
	return nil
}

// rowsByKey reads the rows named by entries' keys: WHERE (key columns) IN (VALUES …).
func (s *Store) rowsByKey(ctx context.Context, t auditTable, cols []string, entries []chainEntry) (map[string][]any, error) {
	var args []any
	tuples := make([]string, 0, len(entries))
	ph := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(t.key)), ", ") + ")"
	for _, e := range entries {
		vals, err := decodeKey(t, e.key)
		if err != nil {
			return nil, err
		}
		args = append(args, vals...)
		tuples = append(tuples, ph)
	}
	q := `SELECT ` + strings.Join(cols, ", ") + ` FROM ` + t.name +
		` WHERE (` + strings.Join(t.key, ", ") + `) IN (VALUES ` + strings.Join(tuples, ", ") + `)`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]any{}
	for rows.Next() {
		vals := make([]any, len(cols))
		dest := make([]any, len(cols))
		for i := range vals {
			dest[i] = &vals[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		byName := make(map[string]any, len(cols))
		for i, c := range cols {
			byName[c] = vals[i]
		}
		key, err := rowKey(t, byName)
		if err != nil {
			return nil, err
		}
		out[key] = vals
	}
	return out, rows.Err()
}

func decodeKey(t auditTable, key string) ([]any, error) {
	if t.intKey() {
		var id int64
		if _, err := fmt.Sscan(key, &id); err != nil {
			return nil, fmt.Errorf("%s: bad key %q", t.name, key)
		}
		return []any{id}, nil
	}
	var vals []any
	dec := json.NewDecoder(strings.NewReader(key))
	dec.UseNumber()
	if err := dec.Decode(&vals); err != nil || len(vals) != len(t.key) {
		return nil, fmt.Errorf("%s: bad key %q", t.name, key)
	}
	for i, v := range vals {
		if n, ok := v.(json.Number); ok {
			x, err := n.Int64()
			if err != nil {
				return nil, fmt.Errorf("%s: bad key %q", t.name, key)
			}
			vals[i] = x
		}
	}
	return vals, nil
}

// RecordAuditVerification records the outcome of a verification.
func (s *Store) RecordAuditVerification(ctx context.Context, r AuditReport, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_verifications (at, head_seq, ok, problems) VALUES (?, ?, ?, ?)`,
		ts(now), r.Head.Seq, boolInt(r.OK()), r.Count)
	return err
}

// LastAuditVerification returns when the chain was last verified (zero if never).
func (s *Store) LastAuditVerification(ctx context.Context) (time.Time, error) {
	var at sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT at FROM audit_verifications ORDER BY id DESC LIMIT 1`).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return parseNullTS(at), err
}
