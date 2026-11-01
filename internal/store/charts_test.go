package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestChartRenders(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	if _, err := s.RecordChartRender(ctx, ChartRender{Chart: "web"}); err == nil {
		t.Error("a render needs a version, profile and digest")
	}
	base := ChartRender{
		Chart: "web", Version: "1.0.0", AppVersion: "1.0", Digest: "sha256:a", Profile: "prod", ProfileHash: "h1",
		ReleasedAt: now.Add(-48 * time.Hour), Images: []ChartImage{{Ref: "index.docker.io/library/nginx:1.27"}, {Ref: "ghcr.io/org/job:1", Hook: true}},
		Invalid: 1, Opaque: 2, RenderedAt: now,
	}
	for _, r := range []ChartRender{
		base,
		func() ChartRender { r := base; r.Profile, r.Images = "dev", nil; return r }(),
		func() ChartRender {
			r := base
			r.Version, r.Digest, r.ReleasedAt, r.RenderedAt = "1.1.0", "sha256:b", time.Time{}, now.Add(time.Hour)
			return r
		}(),
		func() ChartRender { r := base; r.Chart = "api"; return r }(),
	} {
		if _, err := s.RecordChartRender(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	web, err := s.ChartRenders(ctx, "web")
	if err != nil || len(web) != 3 {
		t.Fatalf("renders of web: %+v %v", web, err)
	}
	if got := web[0]; got.Images[1] != (ChartImage{Ref: "ghcr.io/org/job:1", Hook: true}) || !got.ReleasedAt.Equal(base.ReleasedAt) || got.Invalid != 1 || got.Opaque != 2 {
		t.Errorf("render read back: %+v", got)
	}
	if web[1].Images == nil || len(web[1].Images) != 0 || !web[2].ReleasedAt.IsZero() {
		t.Errorf("no images, no release time: %+v", web[1:])
	}
	all, _ := s.ChartRenders(ctx, "")
	latest := LatestChartRenders(all)
	if len(all) != 4 || latest["web"]["prod"].Version != "1.1.0" || latest["web"]["dev"].Version != "1.0.0" || len(latest["api"]) != 1 {
		t.Errorf("latest: %+v", latest)
	}

	if _, err := s.db.ExecContext(ctx, `UPDATE chart_renders SET images = '[]'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("chart_renders is append-only: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM chart_renders`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("chart_renders is append-only: %v", err)
	}
	rep, err := s.VerifyAudit(ctx, nil)
	if err != nil || !rep.OK() {
		t.Fatalf("audit: %+v %v", rep, err)
	}
	if _, err := s.db.ExecContext(ctx, `DROP TRIGGER chart_renders_no_update;
		UPDATE chart_renders SET images = '[]' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if rep, _ := s.VerifyAudit(ctx, nil); rep.OK() {
		t.Error("a rewritten chart render is detected")
	}
}
