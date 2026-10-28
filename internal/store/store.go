// Package store persists targets, SBOMs, scans, findings and their audit
// trail in SQLite. The schema is kept portable so that a PostgreSQL backend
// can share it (docs/adr/0005-storage.md).
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, keeps the binary cgo-free

	"github.com/nocs90/shieldmon/internal/model"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store is a handle to the ShieldMon database.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the SQLite database at path and applies
// pending migrations. Use ":memory:" for an ephemeral database.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_txlock=immediate"
	if path != ":memory:" {
		dsn += "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
		// Create the file owner-only; SQLite gives -wal/-shm the same mode.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		f.Close()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: serializes writers and keeps :memory: databases alive.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		ver, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return fmt.Errorf("bad migration name %s", e.Name())
		}
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE version = ?`, ver).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return fmt.Errorf("%s: %w", e.Name(), err)
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
				ver, e.Name(), ts(time.Now()))
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	return int(v.Int64), err
}

func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- time and JSON helpers ----

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func nullTS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return ts(t)
}

func parseTS(v string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, v)
	return t
}

func parseNullTS(v sql.NullString) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return parseTS(v.String)
}

func jsonList(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func parseList(v string) []string {
	var out []string
	_ = json.Unmarshal([]byte(v), &out)
	return out
}

// ---- targets and artifacts ----

// Target is a monitored image reference on one platform.
type Target struct {
	ID             int64
	Ref            string
	Platform       string
	CurrentDigest  string
	CreatedAt      time.Time
	LastResolvedAt time.Time
}

// UpsertTarget returns the target for (ref, platform), creating it if needed.
func (s *Store) UpsertTarget(ctx context.Context, ref, platform string, now time.Time) (Target, error) {
	_, err := s.db.ExecContext(ctx, `INSERT INTO targets (ref, platform, created_at) VALUES (?, ?, ?)
		ON CONFLICT (ref, platform) DO NOTHING`, ref, platform, ts(now))
	if err != nil {
		return Target{}, err
	}
	return s.targetWhere(ctx, `ref = ? AND platform = ?`, ref, platform)
}

// GetTarget returns a target by ID.
func (s *Store) GetTarget(ctx context.Context, id int64) (Target, error) {
	return s.targetWhere(ctx, `id = ?`, id)
}

func (s *Store) targetWhere(ctx context.Context, where string, args ...any) (Target, error) {
	ts, err := s.listTargets(ctx, where, args...)
	if err != nil {
		return Target{}, err
	}
	if len(ts) == 0 {
		return Target{}, ErrNotFound
	}
	return ts[0], nil
}

// ListTargets returns all targets ordered by ID.
func (s *Store) ListTargets(ctx context.Context) ([]Target, error) {
	return s.listTargets(ctx, "1 = 1")
}

func (s *Store) listTargets(ctx context.Context, where string, args ...any) ([]Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ref, platform, current_digest, created_at, last_resolved_at
		FROM targets WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		var cur, last sql.NullString
		var created string
		if err := rows.Scan(&t.ID, &t.Ref, &t.Platform, &cur, &created, &last); err != nil {
			return nil, err
		}
		t.CurrentDigest, t.CreatedAt, t.LastResolvedAt = cur.String, parseTS(created), parseNullTS(last)
		out = append(out, t)
	}
	return out, rows.Err()
}

// TargetsForDigest returns the targets whose current digest is digest.
func (s *Store) TargetsForDigest(ctx context.Context, digest string) ([]Target, error) {
	return s.listTargets(ctx, `current_digest = ?`, digest)
}

// Artifact is an immutable scanned image manifest.
type Artifact struct {
	Digest      string
	Repository  string
	IndexDigest string
	MediaType   string
	Platform    string
}

// UpsertArtifact records an artifact the first time it is seen.
func (s *Store) UpsertArtifact(ctx context.Context, a Artifact, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts (digest, repository, index_digest, media_type, platform, first_seen_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (digest) DO NOTHING`,
		a.Digest, a.Repository, a.IndexDigest, a.MediaType, a.Platform, ts(now))
	return err
}

// GetArtifact returns an artifact by digest.
func (s *Store) GetArtifact(ctx context.Context, digest string) (Artifact, error) {
	var a Artifact
	var idx sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT digest, repository, index_digest, media_type, platform FROM artifacts WHERE digest = ?`, digest).
		Scan(&a.Digest, &a.Repository, &idx, &a.MediaType, &a.Platform)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	a.IndexDigest = idx.String
	return a, err
}

// RecordResolution stores the digest a target resolved to. It reports the
// previous digest and whether it changed (a new digest in the lineage).
func (s *Store) RecordResolution(ctx context.Context, targetID int64, digest string, now time.Time) (prev string, changed bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var cur sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT current_digest FROM targets WHERE id = ?`, targetID).Scan(&cur); err != nil {
			return err
		}
		prev = cur.String
		if prev != digest {
			changed = true
			if _, err := tx.ExecContext(ctx, `INSERT INTO target_digests (target_id, digest, previous_digest, observed_at) VALUES (?, ?, ?, ?)`,
				targetID, digest, nullString(prev), ts(now)); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE targets SET current_digest = ?, last_resolved_at = ? WHERE id = ?`, digest, ts(now), targetID)
		return err
	})
	return prev, changed, err
}

func nullString(v string) any {
	if v == "" {
		return nil
	}
	return v
}

// ---- SBOMs ----

// SBOM is a stored SBOM document.
type SBOM struct {
	ID               int64
	Digest           string
	Generator        string
	GeneratorVersion string
	Format           string
	SHA256           string
	Size             int64
	Path             string
	CreatedAt        time.Time
}

// InsertSBOM records a stored SBOM.
func (s *Store) InsertSBOM(ctx context.Context, b SBOM) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sboms (digest, generator, generator_version, format, sha256, size, path, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, b.Digest, b.Generator, b.GeneratorVersion, b.Format, b.SHA256, b.Size, b.Path, ts(b.CreatedAt))
	return err
}

// SBOMs returns the SBOMs stored for a digest.
func (s *Store) SBOMs(ctx context.Context, digest string) ([]SBOM, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, digest, generator, generator_version, format, sha256, size, path, created_at
		FROM sboms WHERE digest = ? ORDER BY id`, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SBOM
	for rows.Next() {
		var b SBOM
		var created string
		if err := rows.Scan(&b.ID, &b.Digest, &b.Generator, &b.GeneratorVersion, &b.Format, &b.SHA256, &b.Size, &b.Path, &created); err != nil {
			return nil, err
		}
		b.CreatedAt = parseTS(created)
		out = append(out, b)
	}
	return out, rows.Err()
}

// ---- scans ----

// Scan statuses.
const (
	ScanRunning  = "running"
	ScanComplete = "complete"
	ScanPartial  = "partial"
	ScanFailed   = "failed"
)

// Scan is one matching run over one digest.
type Scan struct {
	ID         int64
	Digest     string
	TargetID   int64
	Kind       string
	Status     string
	StartedAt  time.Time
	FinishedAt time.Time
	Tools      []model.Tool
	Error      string
}

// CreateScan starts a scan record.
func (s *Store) CreateScan(ctx context.Context, digest string, targetID int64, kind string, now time.Time) (int64, error) {
	var tid any
	if targetID != 0 {
		tid = targetID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO scans (digest, target_id, kind, status, started_at) VALUES (?, ?, ?, 'running', ?)`,
		digest, tid, kind, ts(now))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishScan records the outcome of a scan.
func (s *Store) FinishScan(ctx context.Context, id int64, status string, tools []model.Tool, errMsg string, now time.Time) error {
	tj, err := json.Marshal(tools)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE scans SET status = ?, tools = ?, error = ?, finished_at = ? WHERE id = ?`,
		status, string(tj), nullString(errMsg), ts(now), id)
	return err
}

// LatestScan returns the most recent finished scan of a digest.
func (s *Store) LatestScan(ctx context.Context, digest string) (Scan, error) {
	return s.latestScan(ctx, `digest = ? AND status != 'running'`, digest)
}

// LatestCompleteScan returns the most recent complete scan of a digest: the last full
// evidence for it.
func (s *Store) LatestCompleteScan(ctx context.Context, digest string) (Scan, error) {
	return s.latestScan(ctx, `digest = ? AND status = ?`, digest, ScanComplete)
}

func (s *Store) latestScan(ctx context.Context, where string, args ...any) (Scan, error) {
	var sc Scan
	var tid sql.NullInt64
	var started string
	var finished, errMsg sql.NullString
	var tools string
	err := s.db.QueryRowContext(ctx, `SELECT id, digest, target_id, kind, status, started_at, finished_at, tools, error
		FROM scans WHERE `+where+` ORDER BY id DESC LIMIT 1`, args...).
		Scan(&sc.ID, &sc.Digest, &tid, &sc.Kind, &sc.Status, &started, &finished, &tools, &errMsg)
	if errors.Is(err, sql.ErrNoRows) {
		return sc, ErrNotFound
	}
	if err != nil {
		return sc, err
	}
	sc.TargetID, sc.StartedAt, sc.FinishedAt, sc.Error = tid.Int64, parseTS(started), parseNullTS(finished), errMsg.String
	_ = json.Unmarshal([]byte(tools), &sc.Tools)
	return sc, nil
}

// DigestChange is one entry of the append-only digest history of a target: the first
// resolution (Previous empty) or a change.
type DigestChange struct {
	TargetID   int64
	Digest     string
	Previous   string
	ObservedAt time.Time
}

// DigestHistory returns the digest history of every target, oldest first.
func (s *Store) DigestHistory(ctx context.Context) ([]DigestChange, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, digest, previous_digest, observed_at FROM target_digests ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DigestChange
	for rows.Next() {
		var c DigestChange
		var prev sql.NullString
		var at string
		if err := rows.Scan(&c.TargetID, &c.Digest, &prev, &at); err != nil {
			return nil, err
		}
		c.Previous, c.ObservedAt = prev.String, parseTS(at)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ---- findings ----

// Finding is a stored vulnerability finding on one digest.
type Finding struct {
	model.Match
	ID            int64
	Digest        string
	State         model.State
	FirstDetected time.Time
	CreatedAt     time.Time
	LastSeen      time.Time
	ClosedAt      time.Time
	PredecessorID int64
	// Targets are the refs currently resolving to Digest (may be empty for
	// historical digests).
	Targets []string
}

// SeverityName is the textual severity, for JSON output.
func (f Finding) SeverityName() string { return f.Severity.String() }

// FindingFilter narrows ListFindings.
type FindingFilter struct {
	States      []model.State
	MinSeverity model.Severity
	Digest      string
	TargetID    int64
	VulnID      string
	Limit       int
}

const findingCols = `f.id, f.digest, f.purl, f.vuln_id, f.pkg_key, f.pkg_name, f.pkg_version, f.pkg_type, f.aliases,
	f.severity, f.cvss_score, f.cvss_vector, f.epss, f.kev, f.fix_versions, f.scanners, f.title, f.state,
	f.first_detected_at, f.created_at, f.last_seen_at, f.closed_at, f.predecessor_id, f.fix_state,
	(SELECT group_concat(t.ref || ' (' || t.platform || ')', ', ') FROM targets t WHERE t.current_digest = f.digest)`

func scanFinding(sc interface{ Scan(...any) error }) (Finding, error) {
	var f Finding
	var aliases, sev, fix, scanners, state, first, created, last, fixState string
	var closed, targets sql.NullString
	var pred sql.NullInt64
	var kev int
	err := sc.Scan(&f.ID, &f.Digest, &f.PURL, &f.VulnID, &f.PkgKey, &f.PkgName, &f.PkgVersion, &f.PkgType, &aliases,
		&sev, &f.CVSSScore, &f.CVSSVector, &f.EPSS, &kev, &fix, &scanners, &f.Title, &state,
		&first, &created, &last, &closed, &pred, &fixState, &targets)
	if err != nil {
		return f, err
	}
	f.Aliases, f.FixVersions, f.Scanners = parseList(aliases), parseList(fix), parseList(scanners)
	f.Severity, f.KEV, f.State = model.ParseSeverity(sev), kev != 0, model.State(state)
	f.FirstDetected, f.CreatedAt, f.LastSeen, f.ClosedAt = parseTS(first), parseTS(created), parseTS(last), parseNullTS(closed)
	f.PredecessorID = pred.Int64
	f.FixState = model.FixState(fixState)
	if targets.Valid && targets.String != "" {
		f.Targets = strings.Split(targets.String, ", ")
	}
	return f, nil
}

// ListFindings returns findings matching the filter, most severe first.
func (s *Store) ListFindings(ctx context.Context, flt FindingFilter) ([]Finding, error) {
	where := []string{"1 = 1"}
	var args []any
	if len(flt.States) > 0 {
		ph := make([]string, len(flt.States))
		for i, st := range flt.States {
			ph[i] = "?"
			args = append(args, string(st))
		}
		where = append(where, "f.state IN ("+strings.Join(ph, ", ")+")")
	}
	if flt.Digest != "" {
		where = append(where, "f.digest = ?")
		args = append(args, flt.Digest)
	}
	if flt.TargetID != 0 {
		where = append(where, "f.digest = (SELECT current_digest FROM targets WHERE id = ?)")
		args = append(args, flt.TargetID)
	}
	if flt.VulnID != "" {
		where = append(where, "(f.vuln_id = ? OR f.aliases LIKE ?)")
		args = append(args, flt.VulnID, `%"`+flt.VulnID+`"%`)
	}
	q := `SELECT ` + findingCols + ` FROM findings f WHERE ` + strings.Join(where, " AND ") + ` ORDER BY f.id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		if f.Severity < flt.MinSeverity {
			continue
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortStableFunc(out, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return int(b.Severity - a.Severity)
		}
		if a.CVSSScore != b.CVSSScore {
			if b.CVSSScore > a.CVSSScore {
				return 1
			}
			return -1
		}
		return 0
	})
	if flt.Limit > 0 && len(out) > flt.Limit {
		out = out[:flt.Limit]
	}
	return out, nil
}

// GetFinding returns a finding by ID.
func (s *Store) GetFinding(ctx context.Context, id int64) (Finding, error) {
	f, err := scanFinding(s.db.QueryRowContext(ctx, `SELECT `+findingCols+` FROM findings f WHERE f.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

// Event is an entry of the append-only finding audit trail.
type Event struct {
	ID        int64
	FindingID int64
	At        time.Time
	From      model.State
	To        model.State
	Actor     string
	Reason    string
	ScanID    int64
}

// Events returns the audit trail of one finding (findingID != 0) or of all
// findings, ordered chronologically.
func (s *Store) Events(ctx context.Context, findingID int64) ([]Event, error) {
	q := `SELECT id, finding_id, at, from_state, to_state, actor, reason, scan_id FROM finding_events`
	var args []any
	if findingID != 0 {
		q += ` WHERE finding_id = ?`
		args = append(args, findingID)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY at, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, to string
		var from sql.NullString
		var scan sql.NullInt64
		if err := rows.Scan(&e.ID, &e.FindingID, &at, &from, &to, &e.Actor, &e.Reason, &scan); err != nil {
			return nil, err
		}
		e.At, e.From, e.To, e.ScanID = parseTS(at), model.State(from.String), model.State(to), scan.Int64
		out = append(out, e)
	}
	return out, rows.Err()
}

func insertEvent(ctx context.Context, tx *sql.Tx, findingID int64, from, to model.State, actor, reason string, scanID int64, now time.Time) error {
	var scan any
	if scanID != 0 {
		scan = scanID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO finding_events (finding_id, at, from_state, to_state, actor, reason, scan_id)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, findingID, ts(now), nullString(string(from)), string(to), actor, reason, scan)
	return err
}

// setState updates a finding's state guarded by its expected current state
// and appends the corresponding event.
func setState(ctx context.Context, tx *sql.Tx, id int64, from, to model.State, actor, reason string, scanID int64, now time.Time) error {
	var closed any
	if to.Terminal() {
		closed = ts(now)
	}
	res, err := tx.ExecContext(ctx, `UPDATE findings SET state = ?, closed_at = ? WHERE id = ? AND state = ?`,
		string(to), closed, id, string(from))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("finding #%d is no longer in state %s", id, from)
	}
	return insertEvent(ctx, tx, id, from, to, actor, reason, scanID, now)
}

// Decision is a stored risk acceptance / not-affected statement.
type Decision struct {
	ID            int64
	FindingID     int64
	State         model.State
	Deviation     string
	Justification string
	Author        string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// Decisions returns the decisions recorded for a finding, newest first.
func (s *Store) Decisions(ctx context.Context, findingID int64) ([]Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, finding_id, state, deviation, justification, author, created_at, expires_at
		FROM decisions WHERE finding_id = ? ORDER BY id DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var d Decision
		var st, created string
		var exp sql.NullString
		if err := rows.Scan(&d.ID, &d.FindingID, &st, &d.Deviation, &d.Justification, &d.Author, &created, &exp); err != nil {
			return nil, err
		}
		d.State, d.CreatedAt, d.ExpiresAt = model.State(st), parseTS(created), parseNullTS(exp)
		out = append(out, d)
	}
	return out, rows.Err()
}

// LatestDecisions returns the most recent decision of every finding that has one.
func (s *Store) LatestDecisions(ctx context.Context) (map[int64]Decision, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.finding_id, d.state, d.deviation, d.justification, d.author, d.created_at, d.expires_at
		FROM decisions d WHERE d.id = (SELECT max(id) FROM decisions WHERE finding_id = d.finding_id)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Decision{}
	for rows.Next() {
		var d Decision
		var st, created string
		var exp sql.NullString
		if err := rows.Scan(&d.ID, &d.FindingID, &st, &d.Deviation, &d.Justification, &d.Author, &created, &exp); err != nil {
			return nil, err
		}
		d.State, d.CreatedAt, d.ExpiresAt = model.State(st), parseTS(created), parseNullTS(exp)
		out[d.FindingID] = d
	}
	return out, rows.Err()
}

// DigestsWithPrefix returns stored artifact digests starting with prefix
// (with or without the "sha256:" algorithm).
func (s *Store) DigestsWithPrefix(ctx context.Context, prefix string) ([]string, error) {
	if !strings.Contains(prefix, ":") {
		prefix = "sha256:" + prefix
	}
	rows, err := s.db.QueryContext(ctx, `SELECT digest FROM artifacts WHERE substr(digest, 1, ?) = ? ORDER BY digest`, len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TargetsByRef returns the targets for a normalized reference (any platform).
func (s *Store) TargetsByRef(ctx context.Context, ref string) ([]Target, error) {
	return s.listTargets(ctx, `ref = ?`, ref)
}
