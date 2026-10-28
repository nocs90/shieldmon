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

// NotifyInput returns the active findings, with their lineage and remediation deadline under
// policy p, and the open health findings: what notify.Collect computes events from
// (docs/adr/0015-notifications.md).
func (s *Store) NotifyInput(ctx context.Context, p lifecycle.Policy) ([]notify.Active, []notify.Health, error) {
	rows, err := s.db.QueryContext(ctx, `WITH RECURSIVE lineage (id, root) AS (
			SELECT id, id FROM findings WHERE predecessor_id IS NULL
			UNION ALL
			SELECT f.id, l.root FROM findings f JOIN lineage l ON f.predecessor_id = l.id
		)
		SELECT `+findingCols+`, l.root FROM findings f JOIN lineage l ON l.id = f.id
		WHERE f.state IN (?, ?, ?, ?) ORDER BY f.id`,
		model.StateOpen, model.StateTriaged, model.StateInRemediation, model.StateReopened)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var active []notify.Active
	for rows.Next() {
		var root int64
		f, err := scanFinding(withExtra{rows, []any{&root}})
		if err != nil {
			return nil, nil, err
		}
		active = append(active, notify.Active{
			Finding: notify.Finding{
				ID: f.ID, Lineage: root, VulnID: f.VulnID, Aliases: f.Aliases, Title: f.Title, Severity: f.Severity.String(),
				KEV: f.KEV, CVSS: f.CVSSScore, EPSS: f.EPSS, Package: f.PkgName, Version: f.PkgVersion, PURL: f.PURL,
				FixVersions: f.FixVersions, Digest: f.Digest, Targets: f.Targets, State: string(f.State),
				FirstDetected: f.FirstDetected,
				SLADue:        p.SLADue(lifecycle.Subject{Severity: f.Severity, FirstDetected: f.FirstDetected}),
			},
			Lineage: root, CreatedAt: f.CreatedAt, Carried: f.PredecessorID != 0,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	hs, err := s.ListHealth(ctx, false)
	if err != nil {
		return nil, nil, err
	}
	health := make([]notify.Health, 0, len(hs))
	for _, h := range hs {
		health = append(health, notify.Health{Check: h.Check, Subject: h.Subject, Severity: h.Severity, Detail: h.Detail, FirstSeen: h.FirstSeen})
	}
	return active, health, nil
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
