package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/notify"
)

const lineageCTE = `WITH RECURSIVE lineage (id, root) AS (
		SELECT id, id FROM findings WHERE predecessor_id IS NULL
		UNION ALL
		SELECT f.id, l.root FROM findings f JOIN lineage l ON f.predecessor_id = l.id
	) `

// NotifyInput returns what notify.Collect computes events from (docs/adr/0015-
// notifications.md): the active findings, with their lineage and remediation deadline under
// policy p; the open health findings; the findings closed as fixed since since, with the
// targets of the scans that gave the evidence. The caller sets the times.
func (s *Store) NotifyInput(ctx context.Context, p lifecycle.Policy, since time.Time) (notify.Input, error) {
	var in notify.Input
	rows, err := s.db.QueryContext(ctx, lineageCTE+`SELECT `+findingCols+`, l.root FROM findings f JOIN lineage l ON l.id = f.id
		WHERE f.state IN (?, ?, ?, ?) ORDER BY f.id`,
		model.StateOpen, model.StateTriaged, model.StateInRemediation, model.StateReopened)
	if err != nil {
		return in, err
	}
	defer rows.Close()
	for rows.Next() {
		var root int64
		f, err := scanFinding(withExtra{rows, []any{&root}})
		if err != nil {
			return in, err
		}
		nf := notifyFinding(f, root)
		nf.SLADue = p.SLADue(lifecycle.Subject{Severity: f.Severity, FirstDetected: f.FirstDetected})
		in.Active = append(in.Active, notify.Active{Finding: nf, Lineage: root, CreatedAt: f.CreatedAt, Carried: f.PredecessorID != 0})
	}
	if err := rows.Err(); err != nil {
		return in, err
	}
	hs, err := s.ListHealth(ctx, false)
	if err != nil {
		return in, err
	}
	for _, h := range hs {
		in.Health = append(in.Health, notify.Health{Check: h.Check, Subject: h.Subject, Severity: h.Severity, Detail: h.Detail, FirstSeen: h.FirstSeen})
	}
	in.Fixed, err = s.fixedSince(ctx, since)
	return in, err
}

// fixedSince returns the findings closed as fixed at or after since, with the targets of the
// scans whose evidence closed them.
func (s *Store) fixedSince(ctx context.Context, since time.Time) ([]notify.Fixed, error) {
	// closed_at is compared as text only to narrow the rows, a second early (RFC 3339 strings
	// with fractional seconds do not sort as text within a second, #67); exactly in Go.
	rows, err := s.db.QueryContext(ctx, lineageCTE+`SELECT `+findingCols+`, l.root,
			(SELECT group_concat(DISTINCT t.ref || ' (' || t.platform || ')') FROM finding_events e
			 JOIN scans sc ON sc.id = e.scan_id JOIN targets t ON t.id = sc.target_id
			 WHERE e.finding_id = f.id AND e.to_state = ?)
		FROM findings f JOIN lineage l ON l.id = f.id
		WHERE f.state = ? AND f.closed_at >= ? ORDER BY f.id`,
		model.StateFixed, model.StateFixed, ts(since.Add(-time.Second).Truncate(time.Second)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []notify.Fixed
	for rows.Next() {
		var root int64
		var targets sql.NullString
		f, err := scanFinding(withExtra{rows, []any{&root, &targets}})
		if err != nil {
			return nil, err
		}
		if f.ClosedAt.Before(since) {
			continue
		}
		nf := notifyFinding(f, root)
		nf.Targets = nil
		if targets.String != "" {
			nf.Targets = strings.Split(targets.String, ",")
		}
		out = append(out, notify.Fixed{Finding: nf, Lineage: root, ClosedAt: f.ClosedAt})
	}
	return out, rows.Err()
}

func notifyFinding(f Finding, lineage int64) notify.Finding {
	return notify.Finding{
		ID: f.ID, Lineage: lineage, VulnID: f.VulnID, Aliases: f.Aliases, Title: f.Title, Severity: f.Severity.String(),
		KEV: f.KEV, CVSS: f.CVSSScore, EPSS: f.EPSS, Package: f.PkgName, Version: f.PkgVersion, PURL: f.PURL,
		FixVersions: f.FixVersions, Digest: f.Digest, Targets: f.Targets, State: string(f.State),
		FirstDetected: f.FirstDetected,
	}
}

// withExtra scans the finding columns followed by extra columns.
type withExtra struct {
	sc    interface{ Scan(...any) error }
	extra []any
}

func (w withExtra) Scan(dest ...any) error { return w.sc.Scan(append(dest, w.extra...)...) }

// RecordNotificationEvents stores the events not stored yet (by key) and registers the
// channels not registered yet: a channel receives the events recorded from then on.
func (s *Store) RecordNotificationEvents(ctx context.Context, events []notify.Event, channels []string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, name := range channels {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notification_channels (name, added_at) VALUES (?, ?)
				ON CONFLICT (name) DO NOTHING`, name, ts(now)); err != nil {
				return err
			}
		}
		for _, e := range events {
			payload, err := json.Marshal(e)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO notification_events (key, kind, payload, created_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (key) DO NOTHING`, e.Key, string(e.Kind), string(payload), ts(now)); err != nil {
				return err
			}
		}
		return nil
	})
}

// PendingNotifications returns the events of the given kinds recorded since the channel was
// registered and not sent to it yet, oldest first; none for a channel not registered.
func (s *Store) PendingNotifications(ctx context.Context, channel string, kinds []notify.Kind) ([]notify.Event, error) {
	var added string
	err := s.db.QueryRowContext(ctx, `SELECT added_at FROM notification_channels WHERE name = ?`, channel).Scan(&added)
	if errors.Is(err, sql.ErrNoRows) || len(kinds) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	since := parseTS(added)
	args := []any{channel}
	for _, k := range kinds {
		args = append(args, string(k))
	}
	rows, err := s.db.QueryContext(ctx, `SELECT payload, created_at FROM notification_events e
		WHERE NOT EXISTS (SELECT 1 FROM notifications n WHERE n.channel = ? AND n.event_id = e.id)
		AND kind IN (?`+strings.Repeat(", ?", len(kinds)-1)+`) ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []notify.Event
	for rows.Next() {
		var payload, created string
		if err := rows.Scan(&payload, &created); err != nil {
			return nil, err
		}
		// Compared as times: RFC 3339 strings with fractional seconds do not sort as text.
		if parseTS(created).Before(since) {
			continue
		}
		var e notify.Event
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			return nil, fmt.Errorf("notification event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// NotificationEventsKnown returns which of keys are recorded events.
func (s *Store) NotificationEventsKnown(ctx context.Context, keys []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, k := range keys {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM notification_events WHERE key = ?`, k).Scan(&n); err != nil {
			return nil, err
		}
		out[k] = n > 0
	}
	return out, nil
}

// RecordNotifications records that the events with keys were sent to channel.
func (s *Store) RecordNotifications(ctx context.Context, channel string, keys []string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, k := range keys {
			res, err := tx.ExecContext(ctx, `INSERT INTO notifications (channel, event_id, sent_at)
				SELECT ?, id, ? FROM notification_events WHERE key = ? ON CONFLICT DO NOTHING`, channel, ts(now), k)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				var known int
				if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM notification_events WHERE key = ?`, k).Scan(&known); err != nil {
					return err
				}
				if known == 0 {
					return fmt.Errorf("notification event %q is not recorded", k)
				}
			}
		}
		return nil
	})
}
