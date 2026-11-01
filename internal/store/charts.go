package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Chart tracking records (docs/adr/0034-chart-tracking.md): append-only.

// MaxChartRenderImages bounds the images one render records (the manifest parser's bound).
const MaxChartRenderImages = 10_000

// ChartImage is one image a rendered chart runs.
type ChartImage struct {
	Ref string `json:"ref"`
	// Hook is true when only Helm hooks use it.
	Hook bool `json:"hook,omitempty"`
}

// ChartRender is what one version of a chart runs with one profile.
type ChartRender struct {
	ID         int64
	Chart      string
	Version    string
	AppVersion string
	// ReleasedAt is when the source says the version was released (zero: it does not say).
	ReleasedAt  time.Time
	Digest      string
	Profile     string
	ProfileHash string
	Images      []ChartImage
	// Invalid counts images that are not valid references, Opaque custom resources.
	Invalid    int
	Opaque     int
	RenderedAt time.Time
}

// RecordChartRender appends a render.
func (s *Store) RecordChartRender(ctx context.Context, r ChartRender) (int64, error) {
	if r.Chart == "" || r.Version == "" || r.Profile == "" || r.Digest == "" {
		return 0, fmt.Errorf("a chart render needs a chart, version, profile and digest")
	}
	if len(r.Images) > MaxChartRenderImages {
		return 0, fmt.Errorf("a chart render of %d images: at most %d", len(r.Images), MaxChartRenderImages)
	}
	images := r.Images
	if images == nil {
		images = []ChartImage{}
	}
	data, err := json.Marshal(images)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO chart_renders
			(chart, version, app_version, released_at, digest, profile, profile_hash, images, invalid, opaque, rendered_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Chart, r.Version, r.AppVersion, nullTS(r.ReleasedAt), r.Digest, r.Profile, r.ProfileHash,
			string(data), r.Invalid, r.Opaque, ts(r.RenderedAt))
		if err != nil {
			return err
		}
		id, err = res.LastInsertId()
		return err
	})
	return id, err
}

// CountChartRenders returns how many renders of chart were recorded after since.
func (s *Store) CountChartRenders(ctx context.Context, chart string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM chart_renders WHERE chart = ? AND rendered_at > ?`, chart, ts(since)).Scan(&n)
	return n, err
}

// ChartRenders returns the renders of chart ("": of every chart), oldest first.
func (s *Store) ChartRenders(ctx context.Context, chart string) ([]ChartRender, error) {
	return s.chartRenders(ctx, `(? = '' OR chart = ?)`, chart, chart)
}

// LatestChartRenders returns the latest render of each profile of chart ("": of every
// chart): what it runs now.
func (s *Store) LatestChartRenders(ctx context.Context, chart string) ([]ChartRender, error) {
	return s.chartRenders(ctx, `id IN (SELECT max(id) FROM chart_renders WHERE ? = '' OR chart = ? GROUP BY chart, profile)`, chart, chart)
}

func (s *Store) chartRenders(ctx context.Context, where string, args ...any) ([]ChartRender, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, chart, version, app_version, released_at, digest, profile,
			profile_hash, images, invalid, opaque, rendered_at
		FROM chart_renders WHERE `+where+` ORDER BY id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChartRender
	for rows.Next() {
		var r ChartRender
		var released sql.NullString
		var images, rendered string
		if err := rows.Scan(&r.ID, &r.Chart, &r.Version, &r.AppVersion, &released, &r.Digest, &r.Profile,
			&r.ProfileHash, &images, &r.Invalid, &r.Opaque, &rendered); err != nil {
			return nil, err
		}
		if released.Valid {
			r.ReleasedAt = parseTS(released.String)
		}
		r.RenderedAt = parseTS(rendered)
		if err := json.Unmarshal([]byte(images), &r.Images); err != nil {
			return nil, fmt.Errorf("chart render #%d: images: %w", r.ID, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
