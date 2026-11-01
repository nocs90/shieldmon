package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
)

// ReconcileArgs identifies one finished scan to reconcile.
type ReconcileArgs struct {
	ScanID int64
	Digest string
	// TargetIDs are the targets currently pointing at Digest; their history
	// supplies predecessor findings and regression detection.
	TargetIDs []int64
	Matches   []model.Match
	Complete  bool
	Now       time.Time
}

// ReconcileScan loads the planner input, plans and applies the lifecycle
// changes in a single transaction, and returns the applied plan.
func (s *Store) ReconcileScan(ctx context.Context, a ReconcileArgs) (lifecycle.Plan, error) {
	var plan lifecycle.Plan
	err := s.tx(ctx, func(tx *sql.Tx) error {
		in := lifecycle.Input{Current: a.Matches, Complete: a.Complete, FixedLineage: map[string]bool{}}
		var err error
		if in.OnDigest, err = loadExisting(ctx, tx, `f.digest = ?`, a.Digest); err != nil {
			return err
		}
		if len(a.TargetIDs) > 0 {
			ph := strings.TrimSuffix(strings.Repeat("?, ", len(a.TargetIDs)), ", ")
			hist := `f.digest IN (SELECT digest FROM target_digests WHERE target_id IN (` + ph + `)) AND f.digest != ?`
			args := make([]any, 0, len(a.TargetIDs)+1)
			for _, id := range a.TargetIDs {
				args = append(args, id)
			}
			args = append(args, a.Digest)
			in.Predecessors, err = loadExisting(ctx, tx, hist+
				` AND f.digest NOT IN (SELECT current_digest FROM targets WHERE current_digest IS NOT NULL)
				  AND f.state NOT IN ('fixed', 'superseded', 'withdrawn')`, args...)
			if err != nil {
				return err
			}
			fixed, err := loadExisting(ctx, tx, hist+` AND f.state = 'fixed'`, args...)
			if err != nil {
				return err
			}
			for _, e := range fixed {
				in.FixedLineage[e.LineageKey] = true
			}
		}
		plan = lifecycle.Reconcile(in, a.Now)
		return applyPlan(ctx, tx, a, plan)
	})
	return plan, err
}

func loadExisting(ctx context.Context, tx *sql.Tx, where string, args ...any) ([]lifecycle.Existing, error) {
	rows, err := tx.QueryContext(ctx, `SELECT f.id, f.digest, f.purl, f.vuln_id, f.pkg_key, f.state, f.first_detected_at,
		COALESCE((SELECT d.deviation FROM decisions d WHERE d.finding_id = f.id ORDER BY d.id DESC LIMIT 1), '')
		FROM findings f WHERE `+where+` ORDER BY f.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lifecycle.Existing
	for rows.Next() {
		var e lifecycle.Existing
		var purl, vuln, pkgKey, state, first, deviation string
		if err := rows.Scan(&e.ID, &e.Digest, &purl, &vuln, &pkgKey, &state, &first, &deviation); err != nil {
			return nil, err
		}
		e.Key, e.LineageKey = purl+"|"+vuln, pkgKey+"|"+vuln
		e.State, e.FirstDetected = model.State(state), parseTS(first)
		e.VendorDependency = deviation == string(lifecycle.DeviationVendorDependency)
		out = append(out, e)
	}
	return out, rows.Err()
}

func applyPlan(ctx context.Context, tx *sql.Tx, a ReconcileArgs, p lifecycle.Plan) error {
	now := ts(a.Now)
	for _, c := range p.Creates {
		m := c.Match
		var pred any
		if c.PredecessorID != 0 {
			pred = c.PredecessorID
		}
		var id int64
		err := tx.QueryRowContext(ctx, `INSERT INTO findings (digest, purl, vuln_id, pkg_key, pkg_name, pkg_version, pkg_type,
			aliases, severity, cvss_score, cvss_vector, epss, kev, fix_versions, scanners, title, state,
			first_detected_at, created_at, last_seen_at, last_seen_scan_id, predecessor_id, fix_state)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			a.Digest, m.PURL, m.VulnID, m.PkgKey, m.PkgName, m.PkgVersion, m.PkgType,
			jsonList(m.Aliases), m.Severity.String(), m.CVSSScore, m.CVSSVector, m.EPSS, boolInt(m.KEV),
			jsonList(m.FixVersions), jsonList(m.Scanners), m.Title, string(c.State),
			ts(c.FirstDetected), now, now, a.ScanID, pred, fixState(m)).Scan(&id)
		if err != nil {
			return fmt.Errorf("insert finding %s: %w", m.Key(), err)
		}
		if err := insertEvent(ctx, tx, id, "", c.State, lifecycle.ActorEngine, c.Reason, a.ScanID, a.Now); err != nil {
			return err
		}
		if c.PredecessorID != 0 && c.State.Suppressed() {
			// The decision follows the problem to the successor digest.
			if _, err := tx.ExecContext(ctx, `INSERT INTO decisions (finding_id, state, deviation, justification, author, created_at, expires_at, vex_statement_id)
				SELECT ?, state, deviation, justification, author, ?, expires_at, vex_statement_id FROM decisions WHERE finding_id = ? ORDER BY id DESC LIMIT 1`,
				id, now, c.PredecessorID); err != nil {
				return err
			}
		}
		if err := insertScanMatch(ctx, tx, a.ScanID, id, m); err != nil {
			return err
		}
	}
	for id, m := range p.Seen {
		_, err := tx.ExecContext(ctx, `UPDATE findings SET aliases = ?, severity = ?, cvss_score = ?, cvss_vector = ?, epss = ?, kev = ?,
			fix_versions = ?, fix_state = ?, scanners = ?, title = ?, last_seen_at = ?, last_seen_scan_id = ? WHERE id = ?`,
			jsonList(m.Aliases), m.Severity.String(), m.CVSSScore, m.CVSSVector, m.EPSS, boolInt(m.KEV),
			jsonList(m.FixVersions), fixState(m), jsonList(m.Scanners), m.Title, now, a.ScanID, id)
		if err != nil {
			return err
		}
		if err := insertScanMatch(ctx, tx, a.ScanID, id, m); err != nil {
			return err
		}
	}
	for _, t := range p.Transitions {
		if err := setState(ctx, tx, t.ID, t.From, t.To, lifecycle.ActorEngine, t.Reason, a.ScanID, a.Now); err != nil {
			return err
		}
	}
	return nil
}

func insertScanMatch(ctx context.Context, tx *sql.Tx, scanID, findingID int64, m model.Match) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO scan_matches (scan_id, finding_id, scanners, severity) VALUES (?, ?, ?, ?)`,
		scanID, findingID, jsonList(m.Scanners), m.Severity.String())
	return err
}

func fixState(m model.Match) string {
	if m.FixState == "" {
		return string(model.FixUnknown)
	}
	return string(m.FixState)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func currentState(ctx context.Context, tx *sql.Tx, id int64) (model.State, error) {
	var st string
	err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE id = ?`, id).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("finding #%d: %w", id, ErrNotFound)
	}
	return model.State(st), err
}

// Transition applies a human-initiated state change.
func (s *Store) Transition(ctx context.Context, id int64, to model.State, actor, reason string, now time.Time) error {
	if actor == "" || actor == lifecycle.ActorEngine {
		return fmt.Errorf("a human actor is required")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		from, err := currentState(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := lifecycle.CheckManual(from, to); err != nil {
			return err
		}
		if reason == "" {
			reason = "manual transition"
		}
		return setState(ctx, tx, id, from, to, actor, reason, 0, now)
	})
}

// ApplyDecision records a risk acceptance or not-affected statement under
// policy and moves the finding to the corresponding state. A missing expiry
// is filled from the policy; the applied decision is returned.
func (s *Store) ApplyDecision(ctx context.Context, id int64, d lifecycle.Decision, p lifecycle.Policy, now time.Time) (lifecycle.Decision, error) {
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		d, _, err = applyDecisionTx(ctx, tx, id, d, 0, p, now)
		return err
	})
	return d, err
}

// applyDecisionTx is ApplyDecision inside tx, for the VEX statement vexStatement (0: a
// decision taken by hand); it also returns the decision's id.
func applyDecisionTx(ctx context.Context, tx *sql.Tx, id int64, d lifecycle.Decision, vexStatement int64, p lifecycle.Policy, now time.Time) (lifecycle.Decision, int64, error) {
	var state, sev, first, fixVersions, fixSt string
	err := tx.QueryRowContext(ctx, `SELECT state, severity, first_detected_at, fix_versions, fix_state FROM findings WHERE id = ?`, id).
		Scan(&state, &sev, &first, &fixVersions, &fixSt)
	if errors.Is(err, sql.ErrNoRows) {
		return d, 0, fmt.Errorf("finding #%d: %w", id, ErrNotFound)
	}
	if err != nil {
		return d, 0, err
	}
	m := model.Match{FixVersions: parseList(fixVersions), FixState: model.FixState(fixSt)}
	subj := lifecycle.Subject{
		State: model.State(state), Severity: model.ParseSeverity(sev), FirstDetected: parseTS(first),
		Fixable: m.Fixable(), FixVersions: m.FixVersions,
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = p.DefaultExpiry(d, subj, now)
	}
	if err := p.Validate(d, subj, now); err != nil {
		return d, 0, err
	}
	var stmt any
	if vexStatement != 0 {
		stmt = vexStatement
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO decisions (finding_id, state, deviation, justification, author, created_at, expires_at, vex_statement_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, string(d.State), string(d.Deviation), d.Justification, d.Author, ts(now), nullTS(d.ExpiresAt), stmt)
	if err != nil {
		return d, 0, err
	}
	did, _ := res.LastInsertId()
	reason := fmt.Sprintf("decision #%d: %s", did, d.Justification)
	if d.Deviation != lifecycle.DeviationNone {
		reason = fmt.Sprintf("decision #%d (%s): %s", did, d.Deviation, d.Justification)
	}
	if subj.State == d.State {
		return d, did, insertEvent(ctx, tx, id, subj.State, d.State, d.Author, reason, 0, now)
	}
	return d, did, setState(ctx, tx, id, subj.State, d.State, d.Author, reason, 0, now)
}

// ExpireDecisions reopens suppressed findings whose latest decision expired.
// It returns the IDs of reopened findings.
func (s *Store) ExpireDecisions(ctx context.Context, now time.Time) ([]int64, error) {
	var reopened []int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT f.id, f.state, d.id FROM findings f
			JOIN decisions d ON d.id = (SELECT max(id) FROM decisions WHERE finding_id = f.id)
			WHERE f.state IN ('risk_accepted', 'not_affected') AND d.expires_at IS NOT NULL AND d.expires_at <= ?`, ts(now))
		if err != nil {
			return err
		}
		type exp struct {
			id, did int64
			state   model.State
		}
		var list []exp
		for rows.Next() {
			var e exp
			var st string
			if err := rows.Scan(&e.id, &st, &e.did); err != nil {
				rows.Close()
				return err
			}
			e.state = model.State(st)
			list = append(list, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range list {
			if err := setState(ctx, tx, e.id, e.state, model.StateReopened, lifecycle.ActorEngine,
				fmt.Sprintf("decision #%d expired", e.did), 0, now); err != nil {
				return err
			}
			reopened = append(reopened, e.id)
		}
		return nil
	})
	return reopened, err
}
