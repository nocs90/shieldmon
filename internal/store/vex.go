package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/vex"
)

// VEXStatement is a stored VEX statement (docs/adr/0014-vex.md).
type VEXStatement struct {
	ID int64
	vex.Statement
	ImportedAt time.Time
	ImportedBy string
}

// AddVEXStatements stores the statements not stored yet (same content, whatever document it
// came in) and returns how many were new.
func (s *Store) AddVEXStatements(ctx context.Context, stmts []vex.Statement, by string, now time.Time) (int, error) {
	added := 0
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, st := range stmts {
			res, err := tx.ExecContext(ctx, `INSERT INTO vex_statements
				(key, vuln_id, aliases, digest, repository, purl, any_version, justification, impact, notes,
				 author, stated_at, expires_at, source, imported_at, imported_by)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (key) DO NOTHING`,
				st.Key(), st.VulnID, jsonList(st.Aliases), st.Digest, st.Repository, st.PURL, st.AnyVersion,
				st.Justification, st.Impact, st.Notes, st.Author, ts(st.Timestamp), nullTS(st.ExpiresAt),
				st.Source, ts(now), by)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n > 0 {
				added++
			}
		}
		return nil
	})
	return added, err
}

// VEXStatements returns the statements in force at now, oldest first.
func (s *Store) VEXStatements(ctx context.Context, now time.Time) ([]VEXStatement, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, vuln_id, aliases, digest, repository, purl, any_version,
		justification, impact, notes, author, stated_at, expires_at, source, imported_at, imported_by
		FROM vex_statements ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VEXStatement
	for rows.Next() {
		var v VEXStatement
		var aliases, stated, imported string
		var expires sql.NullString
		if err := rows.Scan(&v.ID, &v.VulnID, &aliases, &v.Digest, &v.Repository, &v.PURL, &v.AnyVersion,
			&v.Justification, &v.Impact, &v.Notes, &v.Author, &stated, &expires, &v.Source, &imported, &v.ImportedBy); err != nil {
			return nil, err
		}
		v.Aliases, v.Timestamp, v.ExpiresAt, v.ImportedAt = parseList(aliases), parseTS(stated), parseNullTS(expires), parseTS(imported)
		if v.InForce(now) {
			out = append(out, v)
		}
	}
	return out, rows.Err()
}

// VEXApplication records that a statement made a finding not_affected.
type VEXApplication struct {
	StatementID, FindingID int64
}

// ApplyVEX applies the statements in force to the active findings they match and have not
// been applied to before, restricted to one digest unless digest is "". Each becomes a
// not_affected decision by the statement's author, under policy p.
func (s *Store) ApplyVEX(ctx context.Context, digest string, p lifecycle.Policy, now time.Time) ([]VEXApplication, error) {
	stmts, err := s.VEXStatements(ctx, now)
	if err != nil || len(stmts) == 0 {
		return nil, err
	}
	byVuln := map[string][]int{}
	for i, st := range stmts {
		for _, id := range append([]string{st.VulnID}, st.Aliases...) {
			byVuln[id] = append(byVuln[id], i)
		}
	}
	applied, err := s.vexApplied(ctx, digest)
	if err != nil {
		return nil, err
	}
	findings, err := s.vexCandidates(ctx, digest)
	if err != nil {
		return nil, err
	}
	var out []VEXApplication
	for _, f := range findings {
		var cands []int
		for _, id := range append([]string{f.VulnID}, f.Aliases...) {
			cands = append(cands, byVuln[id]...)
		}
		sort.Ints(cands)
		for _, i := range cands {
			st := stmts[i]
			if applied[VEXApplication{st.ID, f.id}] || !st.Matches(f.Finding) {
				continue
			}
			// One statement is enough: the finding is not_affected after it.
			if err := s.applyVEXStatement(ctx, st, f.id, p, now); err != nil {
				return out, fmt.Errorf("VEX statement #%d on finding #%d: %w", st.ID, f.id, err)
			}
			out = append(out, VEXApplication{st.ID, f.id})
			break
		}
	}
	return out, nil
}

func (s *Store) applyVEXStatement(ctx context.Context, st VEXStatement, findingID int64, p lifecycle.Policy, now time.Time) error {
	reason := st.Reason()
	if st.Source != "" {
		reason = fmt.Sprintf("%s (VEX statement #%d, %s)", reason, st.ID, st.Source)
	} else {
		reason = fmt.Sprintf("%s (VEX statement #%d)", reason, st.ID)
	}
	d := lifecycle.Decision{State: model.StateNotAffected, Justification: reason, Author: st.Author, ExpiresAt: st.ExpiresAt}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, _, err := applyDecisionTx(ctx, tx, findingID, d, st.ID, p, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO vex_applications (statement_id, finding_id, applied_at) VALUES (?, ?, ?)`,
			st.ID, findingID, ts(now))
		return err
	})
}

func (s *Store) vexApplied(ctx context.Context, digest string) (map[VEXApplication]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT va.statement_id, va.finding_id FROM vex_applications va
		JOIN findings f ON f.id = va.finding_id WHERE ? = '' OR f.digest = ?`, digest, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[VEXApplication]bool{}
	for rows.Next() {
		var a VEXApplication
		if err := rows.Scan(&a.StatementID, &a.FindingID); err != nil {
			return nil, err
		}
		out[a] = true
	}
	return out, rows.Err()
}

type vexCandidate struct {
	id int64
	vex.Finding
}

// vexCandidates returns the active findings, of one digest unless digest is "".
func (s *Store) vexCandidates(ctx context.Context, digest string) ([]vexCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.id, f.digest, a.repository, f.purl, f.pkg_key, f.vuln_id, f.aliases
		FROM findings f JOIN artifacts a ON a.digest = f.digest
		WHERE f.state IN (?, ?, ?, ?) AND (? = '' OR f.digest = ?) ORDER BY f.id`,
		model.StateOpen, model.StateTriaged, model.StateInRemediation, model.StateReopened, digest, digest)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vexCandidate
	for rows.Next() {
		var c vexCandidate
		var aliases string
		if err := rows.Scan(&c.id, &c.Digest, &c.Repository, &c.PURL, &c.PkgKey, &c.VulnID, &aliases); err != nil {
			return nil, err
		}
		c.Aliases = parseList(aliases)
		out = append(out, c)
	}
	return out, rows.Err()
}

// VEXUnknownProducts returns the statements in force whose product ShieldMon has never
// scanned: they are kept, and apply once the product is scanned.
func (s *Store) VEXUnknownProducts(ctx context.Context, now time.Time) ([]VEXStatement, error) {
	stmts, err := s.VEXStatements(ctx, now)
	if err != nil {
		return nil, err
	}
	var out []VEXStatement
	for _, st := range stmts {
		var n int
		err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM artifacts WHERE (? <> '' AND digest = ?) OR (? = '' AND repository = ?)`,
			st.Digest, st.Digest, st.Digest, st.Repository).Scan(&n)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			out = append(out, st)
		}
	}
	return out, nil
}

// ManualNotAffected returns the not_affected findings whose decision was taken by hand, not
// by a VEX statement (also when carried to a successor digest), as statements scoped to
// their digest and package (for export).
func (s *Store) ManualNotAffected(ctx context.Context, now time.Time) ([]vex.Statement, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT f.digest, a.repository, f.purl, f.vuln_id, f.aliases,
			d.justification, d.author, d.created_at, d.expires_at
		FROM findings f
		JOIN artifacts a ON a.digest = f.digest
		JOIN decisions d ON d.id = (SELECT max(id) FROM decisions WHERE finding_id = f.id)
		WHERE f.state = ? AND d.state = ? AND d.vex_statement_id IS NULL
		ORDER BY f.id`, model.StateNotAffected, model.StateNotAffected)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vex.Statement
	for rows.Next() {
		var st vex.Statement
		var aliases, created string
		var expires sql.NullString
		var reason string
		if err := rows.Scan(&st.Digest, &st.Repository, &st.PURL, &st.VulnID, &aliases, &reason, &st.Author, &created, &expires); err != nil {
			return nil, err
		}
		// Seconds, as OpenVEX writes them, so that an export reads back as the same statement.
		st.Aliases = parseList(aliases)
		st.Timestamp = parseTS(created).UTC().Truncate(time.Second)
		if exp := parseNullTS(expires); !exp.IsZero() {
			st.ExpiresAt = exp.UTC().Truncate(time.Second)
		}
		st.Justification, st.Impact = vex.SplitReason(reason)
		if st.InForce(now) {
			out = append(out, st)
		}
	}
	return out, rows.Err()
}
