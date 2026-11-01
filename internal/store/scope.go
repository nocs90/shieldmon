package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Target event actions (docs/adr/0017-target-retirement.md).
const (
	ActionRetire  = "retire"
	ActionRestore = "restore"
)

// TargetEvent is a retirement or restoration of a target.
type TargetEvent struct {
	TargetID int64
	Action   string
	Actor    string
	Reason   string
	At       time.Time
}

// ErrRetirement is returned when a target is already in the state asked for.
var ErrRetirement = errors.New("target already in that state")

// RetireTarget records that a target is no longer monitored; RestoreTarget that it is again.
// Findings are not changed.
func (s *Store) RetireTarget(ctx context.Context, id int64, actor, reason string, now time.Time) error {
	return s.targetEvent(ctx, id, ActionRetire, actor, reason, now)
}

// RestoreTarget records that a retired target is monitored again.
func (s *Store) RestoreTarget(ctx context.Context, id int64, actor, reason string, now time.Time) error {
	return s.targetEvent(ctx, id, ActionRestore, actor, reason, now)
}

func (s *Store) targetEvent(ctx context.Context, id int64, action, actor, reason string, now time.Time) error {
	if actor == "" || len(reason) < 10 {
		return fmt.Errorf("%s needs an actor and a reason of at least 10 characters", action)
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var last sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT (SELECT action FROM target_events WHERE target_id = ? ORDER BY id DESC LIMIT 1)
			FROM targets WHERE id = ?`, id, id).Scan(&last)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		retired := last.String == ActionRetire
		if retired == (action == ActionRetire) {
			return fmt.Errorf("%w: target #%d is %s", ErrRetirement, id, map[bool]string{true: "retired", false: "monitored"}[retired])
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO target_events (target_id, action, actor, reason, at) VALUES (?, ?, ?, ?, ?)`,
			id, action, actor, reason, ts(now))
		return err
	})
}

// TargetEvents returns every retirement and restoration, oldest first.
func (s *Store) TargetEvents(ctx context.Context) ([]TargetEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, action, actor, reason, at FROM target_events ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetEvent
	for rows.Next() {
		var e TargetEvent
		var at string
		if err := rows.Scan(&e.TargetID, &e.Action, &e.Actor, &e.Reason, &at); err != nil {
			return nil, err
		}
		e.At = parseTS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Scope answers whether findings were in scope at a given time: a digest is out of scope when
// every target that resolved to it then was retired (ADR 0017). It is built from append-only
// history, so past answers never change.
type Scope struct {
	digests map[int64][]DigestChange // per target, oldest first
	events  map[int64][]TargetEvent  // per target, oldest first
	users   map[string][]int64       // per digest, the targets that ever resolved to it
}

// NewScope builds a Scope from the digest history and the target events.
func NewScope(history []DigestChange, events []TargetEvent) Scope {
	sc := Scope{digests: map[int64][]DigestChange{}, events: map[int64][]TargetEvent{}, users: map[string][]int64{}}
	for _, c := range history {
		sc.digests[c.TargetID] = append(sc.digests[c.TargetID], c)
		if !slices.Contains(sc.users[c.Digest], c.TargetID) {
			sc.users[c.Digest] = append(sc.users[c.Digest], c.TargetID)
		}
	}
	for _, e := range events {
		sc.events[e.TargetID] = append(sc.events[e.TargetID], e)
	}
	return sc
}

// LoadScope reads the history a Scope needs.
func (s *Store) LoadScope(ctx context.Context) (Scope, error) {
	history, err := s.DigestHistory(ctx)
	if err != nil {
		return Scope{}, err
	}
	events, err := s.TargetEvents(ctx)
	if err != nil {
		return Scope{}, err
	}
	return NewScope(history, events), nil
}

// Retired reports whether digest was out of scope at t: some target resolved to it then, and
// all of those were retired. A digest no target resolved to at t stays in scope.
func (sc Scope) Retired(digest string, t time.Time) bool {
	found := false
	for _, id := range sc.users[digest] {
		if digestAt(sc.digests[id], t) != digest {
			continue
		}
		if !sc.RetiredAt(id, t) {
			return false
		}
		found = true
	}
	return found
}

// RetiredAt reports whether target id was retired at t.
func (sc Scope) RetiredAt(id int64, t time.Time) bool {
	retired := false
	for _, e := range sc.events[id] {
		if e.At.After(t) {
			break
		}
		retired = e.Action == ActionRetire
	}
	return retired
}

func digestAt(changes []DigestChange, t time.Time) string {
	d := ""
	for _, c := range changes {
		if c.ObservedAt.After(t) {
			break
		}
		d = c.Digest
	}
	return d
}
