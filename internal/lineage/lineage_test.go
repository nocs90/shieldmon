package lineage

import (
	"testing"
	"time"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

func TestEvaluate(t *testing.T) {
	old := Observation{Digest: "sha256:b1", DiffIDs: []string{"l1", "l2"}, ObservedAt: now.Add(-200 * day)}
	newer := Observation{Digest: "sha256:b2", DiffIDs: []string{"l1", "l3"}, ObservedAt: now.Add(-10 * day)}
	onOld := Image{DiffIDs: []string{"l1", "l2", "app"}, BaseRef: "registry.test/base:1", Source: SourceConfigured}
	onNew := Image{DiffIDs: []string{"l1", "l3", "app"}, BaseRef: "registry.test/base:1", Source: SourceConfigured}
	other := Image{DiffIDs: []string{"x1", "app"}, BaseRef: "registry.test/base:1", Source: SourceAnnotation}

	for _, c := range []struct {
		name   string
		img    Image
		obs    []Observation
		status Status
		base   string
	}{
		{"no base", Image{DiffIDs: []string{"l1"}}, []Observation{old}, None, ""},
		{"not observed yet", onNew, nil, Unknown, ""},
		{"on the newest", onNew, []Observation{old, newer}, Current, "sha256:b2"},
		{"on an older digest", onOld, []Observation{old, newer}, RebuildAvailable, "sha256:b1"},
		{"shares no layers", other, []Observation{old, newer}, Unknown, ""},
		{"verified annotation, never observed", Image{DiffIDs: other.DiffIDs, BaseRef: other.BaseRef, VerifiedDigest: "sha256:b0"}, []Observation{newer}, RebuildAvailable, "sha256:b0"},
		{"image is the base itself", Image{DiffIDs: []string{"l1", "l3"}, BaseRef: "b"}, []Observation{newer}, Current, "sha256:b2"},
		{"empty base proves nothing", onNew, []Observation{{Digest: "sha256:scratch", ObservedAt: now}}, Unknown, ""},
	} {
		r := Evaluate(c.img, c.obs, 90*day, now)
		if r.Status != c.status || r.BaseDigest != c.base {
			t.Errorf("%s: %s %q, want %s %q", c.name, r.Status, r.BaseDigest, c.status, c.base)
		}
	}
}

func TestUnmaintained(t *testing.T) {
	img := Image{DiffIDs: []string{"l1", "app"}, BaseRef: "b"}
	at := func(observed, created time.Time) Observation {
		return Observation{Digest: "sha256:b", DiffIDs: []string{"l1"}, ObservedAt: observed, Created: created}
	}
	for _, c := range []struct {
		name   string
		obs    []Observation
		want   bool
		source string
	}{
		{"created long ago, never seen moving", []Observation{at(now.Add(-day), now.Add(-150*day))}, true, "created"},
		{"created recently", []Observation{at(now.Add(-day), now.Add(-30*day))}, false, "created"},
		{"reproducible epoch: only what was observed counts", []Observation{at(now.Add(-day), time.Unix(0, 0))}, false, "observed"},
		{"epoch, watched unchanged for long", []Observation{at(now.Add(-100*day), time.Unix(1, 0))}, true, "observed"},
		{"created in the future", []Observation{at(now.Add(-day), now.Add(day))}, false, "observed"},
		{"moved recently: the change is when it was seen", []Observation{
			{Digest: "sha256:a", DiffIDs: []string{"x"}, ObservedAt: now.Add(-300 * day)}, at(now.Add(-5*day), now.Add(-400*day)),
		}, false, "observed"},
	} {
		r := Evaluate(img, c.obs, 90*day, now)
		if r.Unmaintained != c.want || r.SinceSource != c.source {
			t.Errorf("%s: unmaintained %v since %v (%s)", c.name, r.Unmaintained, r.Since, r.SinceSource)
		}
	}
	if r := Evaluate(img, []Observation{at(now.Add(-1000*day), time.Time{})}, 0, now); r.Unmaintained {
		t.Error("max_age 0 never flags")
	}
}
