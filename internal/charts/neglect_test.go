package charts_test

import (
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/model"
)

func TestAssess(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	p := charts.NeglectPolicy{FixableAfter: 30 * day, MinSeverity: model.SeverityHigh, StaleAfter: 180 * day}
	fix := func(img, id string, sev model.Severity, age time.Duration, kev bool) charts.Fixable {
		return charts.Fixable{Image: img, VulnID: id, Severity: sev, FirstDetected: now.Add(-age), KEV: kev, FixVersions: []string{"1.2.4"}}
	}
	r := charts.Release{
		Version: "4.12.0", ReleasedAt: now.Add(-10 * day), Images: []string{"a", "b"},
		Fixable: []charts.Fixable{
			fix("a", "CVE-1", model.SeverityHigh, 40*day, false),
			fix("a", "CVE-2", model.SeverityCritical, 31*day, false),
			fix("b", "CVE-3", model.SeverityHigh, 60*day, true),
			fix("b", "CVE-4", model.SeverityCritical, 29*day, false), // not overdue yet
			fix("b", "CVE-5", model.SeverityMedium, 90*day, false),   // below the policy
		},
	}
	a := charts.Assess(r, p, now)
	if !a.Neglected || a.Stale || len(a.Reasons) != 1 {
		t.Fatalf("assessment: %+v", a)
	}
	var ids []string
	for _, f := range a.Overdue {
		ids = append(ids, f.VulnID)
	}
	if got := strings.Join(ids, ","); got != "CVE-3,CVE-2,CVE-1" {
		t.Errorf("overdue, KEV then severity then oldest: %s", got)
	}
	if !strings.Contains(a.Reasons[0], "3 finding(s) of severity high or higher") || !strings.Contains(a.Reasons[0], "2 image(s) of 4.12.0") {
		t.Errorf("reason: %s", a.Reasons[0])
	}

	// A chart that stopped releasing is neglected even with nothing fixable known.
	old := charts.Release{Version: "1.0.0", ReleasedAt: now.Add(-200 * day)}
	if a := charts.Assess(old, p, now); !a.Neglected || !a.Stale || !strings.Contains(a.Reasons[0], "no release since 2026-04-15 (200 days)") {
		t.Errorf("stale: %+v", a)
	}
	// Unknown release times and zero policies never judge.
	if a := charts.Assess(charts.Release{Version: "1.0.0", Fixable: r.Fixable}, charts.NeglectPolicy{}, now); a.Neglected {
		t.Errorf("no policy, no verdict: %+v", a)
	}
	if a := charts.Assess(charts.Release{Version: "1.0.0"}, p, now); a.Neglected {
		t.Errorf("unknown release time: %+v", a)
	}
}
