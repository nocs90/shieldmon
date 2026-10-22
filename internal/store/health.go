package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// HealthFinding is a failure of the monitoring process itself (F10): stale
// DBs, scanner failures, auth failures, missed schedules.
type HealthFinding struct {
	ID          int64
	Check       string
	Subject     string
	State       string // open | resolved
	Severity    string
	Detail      string
	FirstSeen   time.Time
	LastSeen    time.Time
	ResolvedAt  time.Time
	Occurrences int
}

// RecordHealth opens (or keeps open) a health finding. Detail must already be
// redacted by the caller.
func (s *Store) RecordHealth(ctx context.Context, check, subject, severity, detail string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO health_findings (check_name, subject, state, severity, detail, first_seen_at, last_seen_at)
		VALUES (?, ?, 'open', ?, ?, ?, ?)
		ON CONFLICT (check_name, subject) DO UPDATE SET
			first_seen_at = CASE WHEN state = 'resolved' THEN excluded.first_seen_at ELSE first_seen_at END,
			occurrences   = CASE WHEN state = 'resolved' THEN 1 ELSE occurrences + 1 END,
			state = 'open', severity = excluded.severity, detail = excluded.detail,
			last_seen_at = excluded.last_seen_at, resolved_at = NULL`,
		check, subject, severity, detail, ts(now), ts(now))
	return err
}

// ResolveHealth closes an open health finding because the check now passes.
func (s *Store) ResolveHealth(ctx context.Context, check, subject string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE health_findings SET state = 'resolved', resolved_at = ?
		WHERE check_name = ? AND subject = ? AND state = 'open'`, ts(now), check, subject)
	return err
}

// ListHealth returns health findings, open ones first.
func (s *Store) ListHealth(ctx context.Context, includeResolved bool) ([]HealthFinding, error) {
	q := `SELECT id, check_name, subject, state, severity, detail, first_seen_at, last_seen_at, resolved_at, occurrences FROM health_findings`
	if !includeResolved {
		q += ` WHERE state = 'open'`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY state, last_seen_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthFinding
	for rows.Next() {
		var h HealthFinding
		var first, last string
		var resolved sql.NullString
		if err := rows.Scan(&h.ID, &h.Check, &h.Subject, &h.State, &h.Severity, &h.Detail, &first, &last, &resolved, &h.Occurrences); err != nil {
			return nil, err
		}
		h.FirstSeen, h.LastSeen, h.ResolvedAt = parseTS(first), parseTS(last), parseNullTS(resolved)
		out = append(out, h)
	}
	return out, rows.Err()
}

// MonitorRun is one execution of the monitoring cycle.
type MonitorRun struct {
	ID         int64
	StartedAt  time.Time
	FinishedAt time.Time
	Status     string
	Targets    int
	Errors     int
}

// StartMonitorRun records the beginning of a cycle.
func (s *Store) StartMonitorRun(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO monitor_runs (started_at, status) VALUES (?, 'running')`, ts(now))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishMonitorRun records the outcome of a cycle.
func (s *Store) FinishMonitorRun(ctx context.Context, id int64, status string, targets, errs int, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE monitor_runs SET finished_at = ?, status = ?, targets = ?, errors = ? WHERE id = ?`,
		ts(now), status, targets, errs, id)
	return err
}

// LastMonitorRun returns the most recent finished cycle.
func (s *Store) LastMonitorRun(ctx context.Context) (MonitorRun, error) {
	var r MonitorRun
	var started string
	var finished sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id, started_at, finished_at, status, targets, errors FROM monitor_runs
		WHERE status != 'running' ORDER BY id DESC LIMIT 1`).Scan(&r.ID, &started, &finished, &r.Status, &r.Targets, &r.Errors)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	r.StartedAt, r.FinishedAt = parseTS(started), parseNullTS(finished)
	return r, err
}
