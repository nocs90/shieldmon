package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Tamper-evident audit chain (docs/adr/0018-audit-chain.md).

// auditTable is an audited table: the columns hashed for each column-set version, the key
// that identifies a row for verification, and which rows are sealed.
type auditTable struct {
	name string
	// cols[v-1] are the columns hashed by column-set version v; new rows use the last one.
	cols [][]string
	// key are the key columns: one integer primary key (stable rowid), or a natural key.
	key []string
	// where restricts the rows sealed (scans are sealed once finished).
	where string
}

func (t auditTable) version() int { return len(t.cols) }

func (t auditTable) intKey() bool { return len(t.key) == 1 && t.key[0] == "id" }

// auditTables are sealed in this order. A migration adding a column to one of them appends a
// column-set version: rows sealed before keep verifying with their version.
var auditTables = []auditTable{
	{name: "target_digests", key: []string{"id"}, cols: [][]string{{"id", "target_id", "digest", "previous_digest", "observed_at"}}},
	{name: "sboms", key: []string{"id"}, cols: [][]string{{"id", "digest", "generator", "generator_version", "format", "sha256", "size", "path", "created_at"}}},
	{name: "scans", key: []string{"id"}, where: "status != 'running'", cols: [][]string{{"id", "digest", "target_id", "kind", "status", "started_at", "finished_at", "tools", "error"}}},
	{name: "scan_matches", key: []string{"scan_id", "finding_id"}, cols: [][]string{{"scan_id", "finding_id", "scanners", "severity"}}},
	{name: "finding_events", key: []string{"id"}, cols: [][]string{{"id", "finding_id", "at", "from_state", "to_state", "actor", "reason", "scan_id"}}},
	{name: "decisions", key: []string{"id"}, cols: [][]string{{"id", "finding_id", "state", "deviation", "justification", "author", "created_at", "expires_at", "vex_statement_id"}}},
	{name: "vex_statements", key: []string{"id"}, cols: [][]string{{
		"id", "key", "vuln_id", "aliases", "digest", "repository", "purl", "any_version", "justification", "impact", "notes",
		"author", "stated_at", "expires_at", "source", "imported_at", "imported_by",
	}}},
	{name: "vex_applications", key: []string{"statement_id", "finding_id"}, cols: [][]string{{"statement_id", "finding_id", "applied_at"}}},
	{name: "target_events", key: []string{"id"}, cols: [][]string{{"id", "target_id", "action", "actor", "reason", "at"}}},
	{name: "notification_events", key: []string{"id"}, cols: [][]string{{"id", "key", "kind", "payload", "created_at"}}},
	{name: "notification_channels", key: []string{"name"}, cols: [][]string{{"name", "added_at"}}},
	{name: "notifications", key: []string{"channel", "event_id"}, cols: [][]string{{"channel", "event_id", "sent_at"}}},
	{name: "target_bases", key: []string{"id"}, cols: [][]string{{"id", "target_id", "base_ref", "actor", "at"}}},
	{name: "image_inspections", key: []string{"digest"}, cols: [][]string{{
		"digest", "diff_ids", "created", "annotated_base", "annotated_repository", "annotated_digest", "annotated_verified",
		"problems", "inspected_at",
	}}},
	{name: "base_observations", key: []string{"id"}, cols: [][]string{{"id", "base_ref", "platform", "digest", "diff_ids", "created", "observed_at"}}},
}

func auditTableNamed(name string) (auditTable, bool) {
	for _, t := range auditTables {
		if t.name == name {
			return t, true
		}
	}
	return auditTable{}, false
}

// genesis is the previous hash of the first entry.
var genesis = strings.Repeat("0", 64)

// sealBatch bounds the rows read before they are chained (one connection: no cursor may stay
// open while inserting).
const sealBatch = 1000

// AuditDigest is the head of the chain: what to export as an anchor.
type AuditDigest struct {
	Format string    `json:"format"`
	Seq    int64     `json:"seq"`
	Hash   string    `json:"hash"`
	At     time.Time `json:"at"`
}

// DigestFormat names the digest document format.
const DigestFormat = "shieldmon-audit-digest/v1"

// rowHash is the SHA-256 of a row's canonical encoding: its columns as a JSON object (keys
// sorted by encoding/json) of typed values, so that no two distinct rows encode alike: 5 and
// "5" differ, and text that is not UTF-8 (which JSON would replace) is kept as bytes.
func rowHash(table string, cols []string, vals []any) (string, error) {
	m := make(map[string]any, len(cols))
	for i, c := range cols {
		v, err := canonical(vals[i])
		if err != nil {
			return "", fmt.Errorf("%s.%s: %w", table, c, err)
		}
		m[c] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(table+"\x00"), b...))
	return hex.EncodeToString(sum[:]), nil
}

// canonical is a value as a [type, value] pair: null, i (integer), f (float, shortest
// round-trip text), s (UTF-8 text), b (bytes, base64).
func canonical(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return nil, nil
	case int64:
		return []any{"i", strconv.FormatInt(x, 10)}, nil
	case float64:
		return []any{"f", strconv.FormatFloat(x, 'g', -1, 64)}, nil
	case string:
		if utf8.ValidString(x) {
			return []any{"s", x}, nil
		}
		return []any{"b", base64.StdEncoding.EncodeToString([]byte(x))}, nil
	case []byte:
		return []any{"b", base64.StdEncoding.EncodeToString(x)}, nil
	case bool:
		return []any{"i", map[bool]string{true: "1", false: "0"}[x]}, nil
	case time.Time:
		return []any{"s", ts(x)}, nil
	}
	return nil, fmt.Errorf("unexpected value type %T", v)
}

// linkHash chains an entry to the previous one.
func linkHash(prev string, seq int64, table, key string, cols int, rowHash string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\n%d\n%s\n%s\n%d\n%s", prev, seq, table, key, cols, rowHash)))
	return hex.EncodeToString(sum[:])
}

// rowKey is the key recorded for a row: the integer id, or the natural key as a JSON array.
func rowKey(t auditTable, vals map[string]any) (string, error) {
	if t.intKey() {
		id, ok := vals["id"].(int64)
		if !ok {
			return "", fmt.Errorf("%s: id is %T", t.name, vals["id"])
		}
		return strconv.FormatInt(id, 10), nil
	}
	key := make([]any, len(t.key))
	for i, k := range t.key {
		key[i] = vals[k]
	}
	b, err := json.Marshal(key)
	return string(b), err
}

// sealTx chains the audited rows not chained yet, in table order and rowid order.
func sealTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	var seq int64
	prev := genesis
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	for _, t := range auditTables {
		var hw int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(max(row_id), 0) FROM audit_chain WHERE tbl = ?`, t.name).Scan(&hw); err != nil {
			return err
		}
		for {
			rows, err := readRows(ctx, tx, t, hw)
			if err != nil {
				return err
			}
			for _, r := range rows {
				seq++
				prev, err = insertLink(ctx, tx, t, r, seq, prev, now)
				if err != nil {
					return err
				}
				hw = r.rowid
			}
			if len(rows) < sealBatch {
				break
			}
		}
	}
	return nil
}

// sealRowTx chains one row now (a scan as it finishes, which a later high-water mark could
// pass by if a newer scan finished first).
func sealRowTx(ctx context.Context, tx *sql.Tx, table string, rowid int64, now time.Time) error {
	t, ok := auditTableNamed(table)
	if !ok {
		return fmt.Errorf("%s is not audited", table)
	}
	var seq int64
	prev := genesis
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_chain ORDER BY seq DESC LIMIT 1`).Scan(&seq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	rows, err := readRowsWhere(ctx, tx, t, "rowid = ?", rowid)
	if err != nil || len(rows) == 0 {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM audit_chain WHERE tbl = ? AND row_key = ?`, t.name, rows[0].key).Scan(&n); err != nil || n > 0 {
		return err
	}
	_, err = insertLink(ctx, tx, t, rows[0], seq+1, prev, now)
	return err
}

type auditRow struct {
	rowid int64
	key   string
	vals  []any
}

func readRows(ctx context.Context, tx *sql.Tx, t auditTable, after int64) ([]auditRow, error) {
	return readRowsWhere(ctx, tx, t, "rowid > ? ORDER BY rowid LIMIT "+strconv.Itoa(sealBatch), after)
}

// readRowsWhere reads rows of t with the latest column set; cond is trusted (built here).
func readRowsWhere(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, t auditTable, cond string, args ...any,
) ([]auditRow, error) {
	cols := t.cols[t.version()-1]
	where := cond
	if t.where != "" {
		where = t.where + " AND " + cond
	}
	rows, err := q.QueryContext(ctx, `SELECT rowid, `+strings.Join(cols, ", ")+` FROM `+t.name+` WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		vals := make([]any, len(cols))
		dest := []any{new(int64)}
		for i := range vals {
			dest = append(dest, &vals[i])
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
		out = append(out, auditRow{rowid: *dest[0].(*int64), key: key, vals: vals})
	}
	return out, rows.Err()
}

func insertLink(ctx context.Context, tx *sql.Tx, t auditTable, r auditRow, seq int64, prev string, now time.Time) (string, error) {
	rh, err := rowHash(t.name, t.cols[t.version()-1], r.vals)
	if err != nil {
		return "", err
	}
	h := linkHash(prev, seq, t.name, r.key, t.version(), rh)
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_chain (seq, tbl, row_key, row_id, cols, row_hash, hash, sealed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, seq, t.name, r.key, r.rowid, t.version(), rh, h, ts(now))
	return h, err
}

// SealAudit chains every audited row not chained yet.
func (s *Store) SealAudit(ctx context.Context) error {
	return s.tx(ctx, func(*sql.Tx) error { return nil }) // tx seals on commit
}

// AuditHead returns the digest of the chain head (Seq 0 for an empty chain).
func (s *Store) AuditHead(ctx context.Context) (AuditDigest, error) {
	d := AuditDigest{Format: DigestFormat, Hash: genesis}
	var at string
	err := s.db.QueryRowContext(ctx, `SELECT seq, hash, sealed_at FROM audit_chain ORDER BY seq DESC LIMIT 1`).Scan(&d.Seq, &d.Hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return d, nil
	}
	d.At = parseTS(at)
	return d, err
}
