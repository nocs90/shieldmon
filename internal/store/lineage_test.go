package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTargetBase(t *testing.T) {
	s, id := seed(t)
	ctx := context.Background()
	if err := s.SetTargetBase(ctx, id, "registry.test/base:1", "", now); err == nil {
		t.Error("a base needs an actor")
	}
	if err := s.SetTargetBase(ctx, 999, "registry.test/base:1", "ops", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown target: %v", err)
	}
	if err := s.SetTargetBase(ctx, id, "", "ops", now); !errors.Is(err, ErrBaseUnchanged) {
		t.Errorf("clearing a base never set: %v", err)
	}
	if err := s.SetTargetBase(ctx, id, "registry.test/base:1", "ops", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTargetBase(ctx, id, "registry.test/base:1", "ops", now); !errors.Is(err, ErrBaseUnchanged) {
		t.Errorf("same base twice: %v", err)
	}
	if b, err := s.TargetBases(ctx); err != nil || b[id] != "registry.test/base:1" {
		t.Errorf("bases = %v, %v", b, err)
	}
	if err := s.SetTargetBase(ctx, id, "", "ops", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if b, _ := s.TargetBases(ctx); len(b) != 0 {
		t.Errorf("cleared: %v", b)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE target_bases SET base_ref = 'x'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("target_bases is append-only: %v", err)
	}
}

func TestImageInspectionOncePerDigest(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	in := ImageInspection{
		Digest: "sha256:a", DiffIDs: []string{"sha256:l1", "sha256:l2"}, AnnotatedBase: "registry.test/base:1",
		AnnotatedRepository: "registry.test/base", AnnotatedDigest: "sha256:b", AnnotatedVerified: true,
		Problems: []string{"x"}, InspectedAt: now,
	}
	if _, err := s.Inspection(ctx, "sha256:a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not inspected yet: %v", err)
	}
	if err := s.RecordInspection(ctx, in); err != nil {
		t.Fatal(err)
	}
	again := in
	again.DiffIDs = []string{"sha256:other"}
	if err := s.RecordInspection(ctx, again); err != nil {
		t.Fatal(err)
	}
	got, err := s.Inspections(ctx)
	if err != nil {
		t.Fatal(err)
	}
	g := got["sha256:a"]
	if !slices.Equal(g.DiffIDs, in.DiffIDs) || !g.AnnotatedVerified || g.AnnotatedDigest != "sha256:b" || !g.Created.IsZero() || !g.InspectedAt.Equal(now) {
		t.Errorf("inspection = %+v: the first one is kept", g)
	}
	if one, err := s.Inspection(ctx, "sha256:a"); err != nil || one.AnnotatedBase != in.AnnotatedBase {
		t.Errorf("inspection of one digest: %+v %v", one, err)
	}
}

func TestBaseObservationsOnChange(t *testing.T) {
	s, _ := seed(t)
	ctx := context.Background()
	obs := func(digest string, at time.Time) bool {
		t.Helper()
		changed, err := s.RecordBaseObservation(ctx, BaseObservation{
			BaseRef: "registry.test/base:1", Platform: "linux/amd64", Digest: digest, DiffIDs: []string{"sha256:l-" + digest}, ObservedAt: at,
		})
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if _, err := s.LatestBaseObservation(ctx, "registry.test/base:1", "linux/amd64"); !errors.Is(err, ErrNotFound) {
		t.Errorf("no observation yet: %v", err)
	}
	if !obs("sha256:b1", now) || obs("sha256:b1", now.Add(time.Hour)) || !obs("sha256:b2", now.Add(2*time.Hour)) || !obs("sha256:b1", now.Add(3*time.Hour)) {
		t.Error("recorded only when the reference moves, also back to an older digest")
	}
	// Another platform is another lineage.
	if _, err := s.RecordBaseObservation(ctx, BaseObservation{BaseRef: "registry.test/base:1", Platform: "linux/arm64", Digest: "sha256:b1", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	last, err := s.LatestBaseObservation(ctx, "registry.test/base:1", "linux/amd64")
	if err != nil || last.Digest != "sha256:b1" || !last.ObservedAt.Equal(now.Add(3*time.Hour)) {
		t.Errorf("latest = %+v, %v", last, err)
	}
	all, err := s.BaseObservations(ctx)
	if err != nil || len(all) != 4 || all[0].Digest != "sha256:b1" || all[1].Digest != "sha256:b2" {
		t.Errorf("observations = %+v, %v", all, err)
	}

	// Every lineage record is sealed in the audit chain and verifies.
	if err := s.SealAudit(ctx); err != nil {
		t.Fatal(err)
	}
	rep, err := s.VerifyAudit(ctx, nil)
	if err != nil || !rep.OK() {
		t.Fatalf("audit: %+v %v", rep, err)
	}
	if _, err := s.db.ExecContext(ctx, `PRAGMA foreign_keys = OFF; DROP TRIGGER base_observations_no_update;
		UPDATE base_observations SET digest = 'sha256:forged' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if rep, _ := s.VerifyAudit(ctx, nil); rep.OK() {
		t.Error("a rewritten base observation is detected")
	}
}
