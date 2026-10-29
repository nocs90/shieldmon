package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Base image lineage records (docs/adr/0022-base-image-lineage.md): all append-only.

// ErrBaseUnchanged is returned when a target's configured base is already the one asked for.
var ErrBaseUnchanged = errors.New("target already has that base")

// SetTargetBase records the base configured for a target; an empty baseRef clears it.
func (s *Store) SetTargetBase(ctx context.Context, targetID int64, baseRef, actor string, now time.Time) error {
	if actor == "" {
		return fmt.Errorf("setting a base needs an actor")
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var cur sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT (SELECT base_ref FROM target_bases WHERE target_id = ? ORDER BY id DESC LIMIT 1)
			FROM targets WHERE id = ?`, targetID, targetID).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if cur.String == baseRef {
			return fmt.Errorf("%w: target #%d", ErrBaseUnchanged, targetID)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO target_bases (target_id, base_ref, actor, at) VALUES (?, ?, ?, ?)`,
			targetID, baseRef, actor, ts(now))
		return err
	})
}

// TargetBases returns the base configured for each target that has one.
func (s *Store) TargetBases(ctx context.Context) (map[int64]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, base_ref FROM target_bases ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var ref string
		if err := rows.Scan(&id, &ref); err != nil {
			return nil, err
		}
		if ref == "" {
			delete(out, id)
		} else {
			out[id] = ref
		}
	}
	return out, rows.Err()
}

// TargetBaseChange is a base configured for a target (empty: cleared).
type TargetBaseChange struct {
	TargetID int64
	BaseRef  string
	Actor    string
	At       time.Time
}

// TargetBaseHistory returns every configured base, oldest first.
func (s *Store) TargetBaseHistory(ctx context.Context) ([]TargetBaseChange, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target_id, base_ref, actor, at FROM target_bases ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TargetBaseChange
	for rows.Next() {
		var c TargetBaseChange
		var at string
		if err := rows.Scan(&c.TargetID, &c.BaseRef, &c.Actor, &at); err != nil {
			return nil, err
		}
		c.At = parseTS(at)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ImageInspection is what an image digest was read to be: its layers and base annotations.
type ImageInspection struct {
	Digest  string
	DiffIDs []string
	Created time.Time
	// AnnotatedBase is the base.name annotation when it names a tag; AnnotatedRepository its
	// repository; AnnotatedDigest the claimed base digest, AnnotatedVerified whether that
	// digest's layers are a prefix of the image's.
	AnnotatedBase       string
	AnnotatedRepository string
	AnnotatedDigest     string
	AnnotatedVerified   bool
	// Problems are annotation values that were ignored.
	Problems    []string
	InspectedAt time.Time
}

// RecordInspection stores the inspection of a digest; a digest is inspected once, later
// records are ignored.
func (s *Store) RecordInspection(ctx context.Context, in ImageInspection) error {
	diff, err := json.Marshal(in.DiffIDs)
	if err != nil {
		return err
	}
	problems, err := json.Marshal(in.Problems)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO image_inspections (digest, diff_ids, created, annotated_base,
			annotated_repository, annotated_digest, annotated_verified, problems, inspected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.Digest, string(diff), nullTS(in.Created), in.AnnotatedBase, in.AnnotatedRepository, in.AnnotatedDigest,
			in.AnnotatedVerified, string(problems), ts(in.InspectedAt))
		return err
	})
}

// Inspection returns the inspection of a digest, or ErrNotFound.
func (s *Store) Inspection(ctx context.Context, digest string) (ImageInspection, error) {
	m, err := s.inspections(ctx, `WHERE digest = ?`, digest)
	if err != nil {
		return ImageInspection{}, err
	}
	in, ok := m[digest]
	if !ok {
		return in, ErrNotFound
	}
	return in, nil
}

// Inspections returns the inspections of every digest inspected, by digest.
func (s *Store) Inspections(ctx context.Context) (map[string]ImageInspection, error) {
	return s.inspections(ctx, "")
}

// inspections reads inspections; where is trusted (built here).
func (s *Store) inspections(ctx context.Context, where string, args ...any) (map[string]ImageInspection, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT digest, diff_ids, created, annotated_base, annotated_repository,
		annotated_digest, annotated_verified, problems, inspected_at FROM image_inspections `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ImageInspection{}
	for rows.Next() {
		var in ImageInspection
		var diff, problems, at string
		var created sql.NullString
		if err := rows.Scan(&in.Digest, &diff, &created, &in.AnnotatedBase, &in.AnnotatedRepository, &in.AnnotatedDigest,
			&in.AnnotatedVerified, &problems, &at); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(diff), &in.DiffIDs)
		_ = json.Unmarshal([]byte(problems), &in.Problems)
		in.Created, in.InspectedAt = parseNullTS(created), parseTS(at)
		out[in.Digest] = in
	}
	return out, rows.Err()
}

// BaseObservation is a digest a base reference pointed to on a platform, from when it was
// first seen there.
type BaseObservation struct {
	BaseRef    string
	Platform   string
	Digest     string
	DiffIDs    []string
	Created    time.Time
	ObservedAt time.Time
}

// LatestBaseObservation returns what a base reference last pointed to on a platform.
func (s *Store) LatestBaseObservation(ctx context.Context, ref, platform string) (BaseObservation, error) {
	obs, err := s.baseObservations(ctx, `WHERE base_ref = ? AND platform = ? ORDER BY id DESC LIMIT 1`, ref, platform)
	if err != nil {
		return BaseObservation{}, err
	}
	if len(obs) == 0 {
		return BaseObservation{}, ErrNotFound
	}
	return obs[0], nil
}

// RecordBaseObservation appends o when the reference points to another digest than last
// recorded; it reports whether it did.
func (s *Store) RecordBaseObservation(ctx context.Context, o BaseObservation) (bool, error) {
	diff, err := json.Marshal(o.DiffIDs)
	if err != nil {
		return false, err
	}
	changed := false
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var last sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT digest FROM base_observations WHERE base_ref = ? AND platform = ? ORDER BY id DESC LIMIT 1`,
			o.BaseRef, o.Platform).Scan(&last)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if last.String == o.Digest {
			return nil
		}
		changed = true
		_, err = tx.ExecContext(ctx, `INSERT INTO base_observations (base_ref, platform, digest, diff_ids, created, observed_at)
			VALUES (?, ?, ?, ?, ?, ?)`, o.BaseRef, o.Platform, o.Digest, string(diff), nullTS(o.Created), ts(o.ObservedAt))
		return err
	})
	return changed, err
}

// BaseObservations returns every observation, oldest first.
func (s *Store) BaseObservations(ctx context.Context) ([]BaseObservation, error) {
	return s.baseObservations(ctx, `ORDER BY id`)
}

// baseObservations reads observations; tail is trusted (built here).
func (s *Store) baseObservations(ctx context.Context, tail string, args ...any) ([]BaseObservation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT base_ref, platform, digest, diff_ids, created, observed_at FROM base_observations `+tail, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BaseObservation
	for rows.Next() {
		var o BaseObservation
		var diff, at string
		var created sql.NullString
		if err := rows.Scan(&o.BaseRef, &o.Platform, &o.Digest, &diff, &created, &at); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(diff), &o.DiffIDs)
		o.Created, o.ObservedAt = parseNullTS(created), parseTS(at)
		out = append(out, o)
	}
	return out, rows.Err()
}
