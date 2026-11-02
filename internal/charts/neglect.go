package charts

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// NeglectPolicy says when a followed chart is neglected: its newest release keeps shipping
// images with vulnerabilities that have a fix, or it has stopped releasing
// (docs/adr/0034-chart-tracking.md).
type NeglectPolicy struct {
	// FixableAfter: an active finding with a fix, of at least MinSeverity, in an image of the
	// newest release and first detected longer ago than this (0: never).
	FixableAfter time.Duration
	MinSeverity  model.Severity
	// StaleAfter: no release for longer than this (0: never).
	StaleAfter time.Duration
}

// Fixable is an active finding with a fix in an image a chart runs.
type Fixable struct {
	Image         string         `json:"image"`
	VulnID        string         `json:"vuln_id"`
	Package       string         `json:"package"`
	Version       string         `json:"version"`
	FixVersions   []string       `json:"fix_versions,omitempty"`
	Severity      model.Severity `json:"-"`
	KEV           bool           `json:"kev,omitempty"`
	FirstDetected time.Time      `json:"first_detected"`
}

// Release is what the newest release of a followed chart runs, as far as ShieldMon knows.
type Release struct {
	Version    string
	ReleasedAt time.Time // zero: the source does not say
	Images     []string
	// Unmonitored are images without a scanned target: their findings are not known.
	Unmonitored []string
	// Fixable are the active findings with a fix in the release's images.
	Fixable []Fixable
}

// Assessment says whether a chart is neglected and why.
type Assessment struct {
	Neglected bool     `json:"neglected"`
	Reasons   []string `json:"reasons,omitempty"`
	// Overdue are the findings that make it neglected, most urgent first: KEV, severity,
	// oldest.
	Overdue []Fixable `json:"overdue,omitempty"`
	// Stale is true when it has not released for longer than the policy allows.
	Stale bool `json:"stale,omitempty"`
	// Unmonitored counts the release's images without scan evidence: a chart that is not
	// neglected may still ship vulnerable images there.
	Unmonitored int `json:"unmonitored,omitempty"`
}

// Verdict is the assessment in a few words: neglected and why, unknown, or no.
func (a Assessment) Verdict() string {
	switch {
	case a.Neglected:
		return "yes: " + strings.Join(a.Reasons, "; ")
	case a.Unmonitored > 0:
		return fmt.Sprintf("unknown: %d image(s) not monitored", a.Unmonitored)
	}
	return "no"
}

// Status is what a followed chart's newest recorded release runs, what ShieldMon knows of its
// images, and whether the chart is neglected.
type Status struct {
	Chart string `json:"chart"`
	// Location is where it comes from (Source.Location).
	Location   string        `json:"location,omitempty"`
	Version    string        `json:"version,omitempty"`
	AppVersion string        `json:"app_version,omitempty"`
	ReleasedAt time.Time     `json:"released_at,omitzero"`
	RenderedAt time.Time     `json:"rendered_at,omitzero"`
	Profiles   []string      `json:"profiles"`
	Images     []StatusImage `json:"images"`
	// Lagging are profiles whose latest render is of an older version (it failed since).
	Lagging []string `json:"lagging,omitempty"`
	// Invalid and Opaque count, over the profiles, images that are not references and
	// custom resources.
	Invalid    int        `json:"invalid,omitempty"`
	Opaque     int        `json:"opaque,omitempty"`
	Assessment Assessment `json:"assessment"`
}

// StatusImage is one image of a chart's newest release.
type StatusImage struct {
	Ref      string   `json:"ref"`
	Profiles []string `json:"profiles"`
	Hook     bool     `json:"hook,omitempty"`
	// Monitored is true when a target of the image has been scanned.
	Monitored bool `json:"monitored"`
	// Fixable counts its active findings with a fix.
	Fixable int `json:"fixable"`
}

// Assess applies p to r at now. It is pure: what ShieldMon knows comes in, a verdict goes out.
func Assess(r Release, p NeglectPolicy, now time.Time) Assessment {
	var a Assessment
	if p.FixableAfter > 0 {
		images := map[string]bool{}
		for _, f := range r.Fixable {
			if f.Severity >= p.MinSeverity && now.Sub(f.FirstDetected) > p.FixableAfter {
				a.Overdue = append(a.Overdue, f)
				images[f.Image] = true
			}
		}
		slices.SortStableFunc(a.Overdue, func(x, y Fixable) int {
			if x.KEV != y.KEV {
				if x.KEV {
					return -1
				}
				return 1
			}
			return cmp.Or(cmp.Compare(y.Severity, x.Severity), x.FirstDetected.Compare(y.FirstDetected),
				strings.Compare(x.Image, y.Image), strings.Compare(x.VulnID, y.VulnID))
		})
		if len(a.Overdue) > 0 {
			a.Reasons = append(a.Reasons, fmt.Sprintf("%d finding(s) of severity %s or higher with a fix, detected more than %d days ago, in %d image(s) of %s",
				len(a.Overdue), strings.ToLower(p.MinSeverity.String()), days(p.FixableAfter), len(images), r.Version))
		}
	}
	if p.StaleAfter > 0 && !r.ReleasedAt.IsZero() && now.Sub(r.ReleasedAt) > p.StaleAfter {
		a.Stale = true
		a.Reasons = append(a.Reasons, fmt.Sprintf("no release since %s (%d days)", r.ReleasedAt.Format(time.DateOnly), days(now.Sub(r.ReleasedAt))))
	}
	a.Neglected = len(a.Reasons) > 0
	a.Unmonitored = len(r.Unmonitored)
	return a
}

func days(d time.Duration) int { return int(d / (24 * time.Hour)) }
