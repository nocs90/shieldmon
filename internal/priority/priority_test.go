package priority

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func TestCompute(t *testing.T) {
	for what, c := range map[string]struct {
		in   Input
		want int
	}{
		"nothing known":             {Input{Severity: model.SeverityUnknown, Now: now}, 20},
		"CVSS only":                 {Input{Severity: model.SeverityHigh, CVSS: 7.5, Now: now}, 30},
		"severity stands in":        {Input{Severity: model.SeverityCritical, Now: now}, 38},
		"KEV beats EPSS":            {Input{Severity: model.SeverityHigh, CVSS: 7.5, EPSS: 0.9, KEV: true, Now: now}, 60},
		"EPSS below 1%":             {Input{Severity: model.SeverityHigh, CVSS: 7.5, EPSS: 0.005, Now: now}, 30},
		"EPSS 1%":                   {Input{Severity: model.SeverityHigh, CVSS: 7.5, EPSS: 0.01, Now: now}, 38},
		"EPSS 10%":                  {Input{Severity: model.SeverityHigh, CVSS: 7.5, EPSS: 0.10, Now: now}, 45},
		"EPSS 50% counts fully":     {Input{Severity: model.SeverityHigh, CVSS: 7.5, EPSS: 0.5, Now: now}, 50},
		"fixable":                   {Input{Severity: model.SeverityMedium, CVSS: 5, Fixable: true, Now: now}, 30},
		"due in a month":            {Input{Severity: model.SeverityMedium, CVSS: 5, SLADue: now.AddDate(0, 0, 20), Now: now}, 28},
		"due this week":             {Input{Severity: model.SeverityMedium, CVSS: 5, SLADue: now.AddDate(0, 0, 3), Now: now}, 35},
		"breached":                  {Input{Severity: model.SeverityMedium, CVSS: 5, SLADue: now.Add(-time.Hour), Now: now}, 40},
		"far deadline":              {Input{Severity: model.SeverityLow, CVSS: 2.5, SLADue: now.AddDate(0, 3, 0), Now: now}, 10},
		"everything, capped":        {Input{Severity: model.SeverityCritical, CVSS: 10, KEV: true, Fixable: true, SLADue: now.Add(-time.Hour), Now: now}, 100},
		"hostile CVSS ignored":      {Input{Severity: model.SeverityLow, CVSS: math.NaN(), Now: now}, 10},
		"out-of-range CVSS ignored": {Input{Severity: model.SeverityLow, CVSS: 99, EPSS: math.NaN(), Now: now}, 10},
	} {
		if got := Compute(c.in); got.Value != c.want {
			t.Errorf("%s: %d %q, want %d", what, got.Value, got.Reasons, c.want)
		}
	}
}

func TestReasonsExplainTheScore(t *testing.T) {
	s := Compute(Input{Severity: model.SeverityHigh, CVSS: 8.1, KEV: true, Fixable: true, SLADue: now.AddDate(0, 0, 2), Now: now})
	want := []string{"impact: CVSS 8.1 (+32)", "known exploited (CISA KEV) (+30)", "fix available (+10)", "remediation due within 7 days (+15)"}
	if s.Value != 87 || strings.Join(s.Reasons, "|") != strings.Join(want, "|") {
		t.Errorf("%d %q", s.Value, s.Reasons)
	}
}

// TestSLAProfileChangesTheScore: the same finding scores higher under a stricter profile.
func TestSLAProfileChangesTheScore(t *testing.T) {
	detected := now.AddDate(0, 0, -10)
	in := Input{Severity: model.SeverityCritical, CVSS: 9.8, Now: now}
	in.SLADue = detected.AddDate(0, 0, 30) // standard: 20 days left
	standard := Compute(in).Value
	in.SLADue = detected.AddDate(0, 0, 15) // strict: 5 days left
	if strict := Compute(in).Value; strict <= standard {
		t.Errorf("strict %d must exceed standard %d", strict, standard)
	}
}
