// Package priority computes a finding's remediation priority (docs/adr/0020-priority-score.md):
// a deterministic score from 0 to 100 with the reasons that make it up. It is pure: the time
// is passed in.
package priority

import (
	"fmt"
	"math"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// Input is what the score is computed from.
type Input struct {
	Severity model.Severity
	// CVSS is the base score (0-10); 0 when unknown, then Severity stands in.
	CVSS float64
	// EPSS is the probability of exploitation in the next 30 days (0-1).
	EPSS float64
	KEV  bool
	// Fixable is true when a fixed version is known.
	Fixable bool
	// SLADue is the remediation deadline under the policy profile; zero when none.
	SLADue time.Time
	Now    time.Time
	// Runtime context (docs/adr/0029-runtime-context.md), from the configured cluster
	// inventories: running pods using the image, and how one is reachable from outside the
	// cluster ("" when none is).
	RunningPods int
	Exposure    string
}

// Score is the priority and its parts, highest first.
type Score struct {
	Value   int      `json:"value"`
	Reasons []string `json:"reasons"`
}

// Weights, documented in ADR 0020. They add up to 100.
const (
	maxImpact      = 40 // CVSS x 4
	kevPoints      = 30 // exploited in the wild
	maxEPSSPoints  = 20 // EPSS >= 50%; 15 from 10%, 8 from 1% (most CVEs are below 1%)
	fixablePoints  = 10 // remediation is an upgrade away
	breachedPoints = 20
	dueWeekPoints  = 15
	dueMonthPoints = 8
	runningPoints  = 5  // ADR 0029: the image runs in a monitored cluster
	exposedPoints  = 10 // … and a pod using it is reachable from outside the cluster
)

// severityCVSS stands in for a missing CVSS score.
var severityCVSS = map[model.Severity]float64{
	model.SeverityCritical: 9.5, model.SeverityHigh: 7.5, model.SeverityMedium: 5.0,
	model.SeverityLow: 2.5, model.SeverityNegligible: 0.5, model.SeverityUnknown: 5.0,
}

// Compute returns the score of in.
func Compute(in Input) Score {
	var s Score
	add := func(points int, reason string) {
		if points > 0 {
			s.Value += points
			s.Reasons = append(s.Reasons, fmt.Sprintf("%s (+%d)", reason, points))
		}
	}
	cvss, source := in.CVSS, "CVSS"
	if cvss <= 0 || cvss > 10 || math.IsNaN(cvss) {
		cvss, source = severityCVSS[in.Severity], "severity "+in.Severity.String()
	}
	add(int(math.Round(cvss*maxImpact/10)), fmt.Sprintf("impact: %s %.1f", source, cvss))
	switch {
	case in.KEV:
		add(kevPoints, "known exploited (CISA KEV)")
	case in.EPSS >= 0.5:
		add(maxEPSSPoints, fmt.Sprintf("EPSS %.1f%%", in.EPSS*100))
	case in.EPSS >= 0.1:
		add(15, fmt.Sprintf("EPSS %.1f%%", in.EPSS*100))
	case in.EPSS >= 0.01:
		add(8, fmt.Sprintf("EPSS %.1f%%", in.EPSS*100))
	}
	if in.Fixable {
		add(fixablePoints, "fix available")
	}
	if !in.SLADue.IsZero() {
		left := in.SLADue.Sub(in.Now)
		switch {
		case left <= 0:
			add(breachedPoints, "remediation deadline passed")
		case left <= 7*24*time.Hour:
			add(dueWeekPoints, "remediation due within 7 days")
		case left <= 30*24*time.Hour:
			add(dueMonthPoints, "remediation due within 30 days")
		}
	}
	if in.RunningPods > 0 {
		add(runningPoints, fmt.Sprintf("running in %d pod(s)", in.RunningPods))
		if in.Exposure != "" {
			add(exposedPoints, "reachable from outside the cluster: "+in.Exposure)
		}
	}
	s.Value = min(s.Value, 100)
	return s
}
