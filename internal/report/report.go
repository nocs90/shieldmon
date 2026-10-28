// Package report derives lifecycle reports from the append-only finding
// audit trail. The monthly report is a view over continuous monitoring data,
// not a separate process.
package report

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/store"
)

// Source is the subset of the store the report needs.
type Source interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]store.Finding, error)
	Events(ctx context.Context, findingID int64) ([]store.Event, error)
	ListHealth(ctx context.Context, includeResolved bool) ([]store.HealthFinding, error)
	ListTargets(ctx context.Context) ([]store.Target, error)
	LatestDecisions(ctx context.Context) (map[int64]store.Decision, error)
	// LoadScope says when findings were out of scope because their images were retired.
	LoadScope(ctx context.Context) (store.Scope, error)
	// AuditHead is the audit chain head the report is anchored to (ADR 0018).
	AuditHead(ctx context.Context) (store.AuditDigest, error)
	ChangesSource
}

// Period is a half-open time interval [Start, End).
type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// MonthPeriod returns the calendar month containing t, in UTC.
func MonthPeriod(t time.Time) Period {
	t = t.UTC()
	start := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
	return Period{Start: start, End: start.AddDate(0, 1, 0)}
}

// Summary holds the headline lifecycle numbers for the period.
type Summary struct {
	OpenAtStart    int     `json:"open_at_start"`
	OpenAtEnd      int     `json:"open_at_end"`
	Opened         int     `json:"opened"`
	Reopened       int     `json:"reopened"`
	Fixed          int     `json:"fixed"`
	Withdrawn      int     `json:"withdrawn"`
	RiskAccepted   int     `json:"risk_accepted"`
	NotAffected    int     `json:"not_affected"`
	MTTRMeanDays   float64 `json:"mttr_mean_days"`
	MTTRMedianDays float64 `json:"mttr_median_days"`
	SLABreaches    int     `json:"sla_breaches"`
	KEVOpen        int     `json:"kev_open"`
	WontFixOpen    int     `json:"wont_fix_open"`
	// RetiredWithAsset counts findings still open whose images were all retired: out of the
	// open numbers, not fixed (ADR 0017).
	RetiredWithAsset int `json:"retired_with_asset"`
}

// Row is one finding as of the end of the period.
type Row struct {
	ID            int64     `json:"id"`
	Targets       []string  `json:"targets,omitempty"`
	Digest        string    `json:"digest"`
	VulnID        string    `json:"vuln_id"`
	Aliases       []string  `json:"aliases,omitempty"`
	Package       string    `json:"package"`
	Version       string    `json:"version"`
	PURL          string    `json:"purl"`
	Severity      string    `json:"severity"`
	CVSS          float64   `json:"cvss,omitempty"`
	EPSS          float64   `json:"epss,omitempty"`
	KEV           bool      `json:"kev,omitempty"`
	FixVersions   []string  `json:"fix_versions,omitempty"`
	FixState      string    `json:"fix_state"`
	Title         string    `json:"title,omitempty"`
	State         string    `json:"state"`
	FirstDetected time.Time `json:"first_detected"`
	AgeDays       int       `json:"age_days"`
	SLADue        time.Time `json:"sla_due,omitzero"`
	SLABreached   bool      `json:"sla_breached"`
	ClosedAt      time.Time `json:"closed_at,omitzero"`
	// Decision is the latest risk acceptance / not-affected statement, if any.
	Decision *DecisionInfo `json:"decision,omitempty"`
}

// DecisionInfo summarizes a decision for reports.
type DecisionInfo struct {
	State         string    `json:"state"`
	Deviation     string    `json:"deviation,omitempty"`
	Author        string    `json:"author"`
	Justification string    `json:"justification"`
	ExpiresAt     time.Time `json:"expires_at,omitzero"`
}

// TargetSummary is the open-finding picture of one monitored target.
type TargetSummary struct {
	Ref      string         `json:"ref"`
	Platform string         `json:"platform"`
	Digest   string         `json:"digest"`
	Open     int            `json:"open"`
	BySev    map[string]int `json:"open_by_severity"`
	Breached int            `json:"sla_breaches"`
	// RetiredAt is when the target was retired, zero while monitored.
	RetiredAt time.Time `json:"retired_at,omitzero"`
}

// DayCount is one point of the burndown series.
type DayCount struct {
	Day  string `json:"day"`
	Open int    `json:"open"`
}

// Monthly is the monthly lifecycle report.
type Monthly struct {
	Period           Period                `json:"period"`
	GeneratedAt      time.Time             `json:"generated_at"`
	SLAProfile       string                `json:"sla_profile"`
	Targets          int                   `json:"targets"`
	Summary          Summary               `json:"summary"`
	OpenBySeverity   map[string]int        `json:"open_by_severity"`
	Aging            map[string]int        `json:"aging"`
	Burndown         []DayCount            `json:"burndown"`
	Open             []Row                 `json:"open"`
	FixedInPeriod    []Row                 `json:"fixed_in_period"`
	AcceptedRisks    []Row                 `json:"accepted_risks"`
	RetiredWithAsset []Row                 `json:"retired_with_asset"`
	HealthOpen       []store.HealthFinding `json:"health_open"`
	TargetSummaries  []TargetSummary       `json:"target_summaries"`
	// InventoryChanges are the images added, rebuilt, retired and restored in the period.
	InventoryChanges Changes `json:"inventory_changes"`
	// AuditDigest is the head of the audit chain when the report was generated: every
	// distributed report anchors the audit trail ('shieldmon audit verify --digest').
	AuditDigest store.AuditDigest `json:"audit_digest"`
}

// AgingBuckets are the age buckets for open findings, in days.
var AgingBuckets = []struct {
	Label string
	Max   int
}{{"0-30", 30}, {"31-60", 60}, {"61-90", 90}, {"91-180", 180}, {"180+", 1 << 30}}

// BuildMonthly computes the report for period p.
func BuildMonthly(ctx context.Context, src Source, p Period, profile string, sla config.SLA, now time.Time) (Monthly, error) {
	r := Monthly{
		Period: p, GeneratedAt: now.UTC(), SLAProfile: profile,
		OpenBySeverity: map[string]int{}, Aging: map[string]int{},
	}
	findings, err := src.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return r, err
	}
	events, err := src.Events(ctx, 0)
	if err != nil {
		return r, err
	}
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return r, err
	}
	r.Targets = len(targets)
	decisions, err := src.LatestDecisions(ctx)
	if err != nil {
		return r, err
	}
	scope, err := src.LoadScope(ctx)
	if err != nil {
		return r, err
	}
	byTarget := map[string]*TargetSummary{}
	for _, t := range targets {
		key := t.Ref + " (" + t.Platform + ")"
		byTarget[key] = &TargetSummary{Ref: t.Ref, Platform: t.Platform, Digest: t.CurrentDigest, BySev: map[string]int{}, RetiredAt: t.RetiredAt}
	}
	// open: a finding counts as open at t when its state is active and its images were not
	// all retired then.
	open := func(f store.Finding, evs []store.Event, t time.Time) bool {
		return stateAt(evs, t).Active() && !scope.Retired(f.Digest, t)
	}
	withDecision := func(rw Row, f store.Finding) Row {
		if d, ok := decisions[f.ID]; ok {
			rw.Decision = &DecisionInfo{
				State: string(d.State), Deviation: d.Deviation, Author: d.Author,
				Justification: d.Justification, ExpiresAt: d.ExpiresAt,
			}
		}
		return rw
	}
	byFinding := map[int64][]store.Event{}
	for _, e := range events {
		byFinding[e.FindingID] = append(byFinding[e.FindingID], e)
	}

	// The report is "as of" the end of the period, or now for the current month.
	asOf := p.End
	if now.Before(asOf) {
		asOf = now
	}

	var mttr []float64
	for _, f := range findings {
		evs := byFinding[f.ID]
		if open(f, evs, p.Start) {
			r.Summary.OpenAtStart++
		}
		for _, e := range evs {
			if e.At.Before(p.Start) || !e.At.Before(p.End) {
				continue
			}
			// A finding carried over to a successor digest continues an existing
			// lineage: its creation event is not a lifecycle event.
			if e.From == "" && f.PredecessorID != 0 {
				continue
			}
			switch e.To {
			case model.StateOpen:
				if e.From == "" {
					r.Summary.Opened++
				}
			case model.StateReopened:
				r.Summary.Reopened++
			case model.StateFixed:
				r.Summary.Fixed++
				days := e.At.Sub(f.FirstDetected).Hours() / 24
				mttr = append(mttr, days)
				r.FixedInPeriod = append(r.FixedInPeriod, row(f, model.StateFixed, e.At, sla))
			case model.StateWithdrawn:
				r.Summary.Withdrawn++
			case model.StateRiskAccepted:
				if e.From != model.StateRiskAccepted {
					r.Summary.RiskAccepted++
				}
			case model.StateNotAffected:
				if e.From != model.StateNotAffected {
					r.Summary.NotAffected++
				}
			}
		}
		st := stateAt(evs, asOf)
		switch {
		case st.Active() && scope.Retired(f.Digest, asOf):
			r.Summary.RetiredWithAsset++
			r.RetiredWithAsset = append(r.RetiredWithAsset, withDecision(row(f, st, asOf, sla), f))
		case st.Active():
			rw := row(f, st, asOf, sla)
			r.Summary.OpenAtEnd++
			r.OpenBySeverity[rw.Severity]++
			r.Aging[agingBucket(rw.AgeDays)]++
			if rw.SLABreached {
				r.Summary.SLABreaches++
			}
			if f.KEV {
				r.Summary.KEVOpen++
			}
			if f.FixState == model.FixWontFix {
				r.Summary.WontFixOpen++
			}
			for _, t := range f.Targets {
				if ts, ok := byTarget[t]; ok {
					ts.Open++
					ts.BySev[rw.Severity]++
					if rw.SLABreached {
						ts.Breached++
					}
				}
			}
			r.Open = append(r.Open, withDecision(rw, f))
		case st.Suppressed():
			r.AcceptedRisks = append(r.AcceptedRisks, withDecision(row(f, st, asOf, sla), f))
		}
	}
	r.Summary.MTTRMeanDays, r.Summary.MTTRMedianDays = meanMedian(mttr)

	for d := p.Start; d.Before(p.End) && !d.After(asOf); d = d.AddDate(0, 0, 1) {
		eod := d.AddDate(0, 0, 1)
		if eod.After(asOf) {
			eod = asOf
		}
		n := 0
		for _, f := range findings {
			if open(f, byFinding[f.ID], eod) {
				n++
			}
		}
		r.Burndown = append(r.Burndown, DayCount{Day: d.Format(time.DateOnly), Open: n})
	}

	sortRows(r.Open)
	sortRows(r.AcceptedRisks)
	sortRows(r.RetiredWithAsset)
	slices.SortFunc(r.FixedInPeriod, func(a, b Row) int { return a.ClosedAt.Compare(b.ClosedAt) })

	for _, t := range targets {
		r.TargetSummaries = append(r.TargetSummaries, *byTarget[t.Ref+" ("+t.Platform+")"])
	}
	slices.SortStableFunc(r.TargetSummaries, func(a, b TargetSummary) int { return cmp.Compare(b.Open, a.Open) })

	health, err := src.ListHealth(ctx, false)
	if err != nil {
		return r, err
	}
	r.HealthOpen = health
	if r.InventoryChanges, err = BuildChanges(ctx, src, p); err != nil {
		return r, err
	}
	r.AuditDigest, err = src.AuditHead(ctx)
	return r, err
}

// stateAt replays a finding's events up to and including t.
func stateAt(evs []store.Event, t time.Time) model.State {
	var st model.State
	for _, e := range evs {
		if e.At.After(t) {
			break
		}
		st = e.To
	}
	return st
}

func row(f store.Finding, st model.State, asOf time.Time, sla config.SLA) Row {
	rw := Row{
		ID: f.ID, Targets: f.Targets, Digest: f.Digest, VulnID: f.VulnID, Aliases: f.Aliases,
		Package: f.PkgName, Version: f.PkgVersion, PURL: f.PURL, Severity: f.Severity.String(),
		CVSS: f.CVSSScore, EPSS: f.EPSS, KEV: f.KEV, FixVersions: f.FixVersions,
		FixState: string(f.FixState), Title: f.Title,
		State: string(st), FirstDetected: f.FirstDetected,
	}
	end := asOf
	if st.Terminal() {
		rw.ClosedAt = asOf
	}
	rw.AgeDays = int(end.Sub(f.FirstDetected).Hours() / 24)
	if days := sla[f.Severity]; days > 0 {
		rw.SLADue = f.FirstDetected.AddDate(0, 0, days)
		rw.SLABreached = end.After(rw.SLADue)
	}
	return rw
}

func agingBucket(days int) string {
	for _, b := range AgingBuckets {
		if days <= b.Max {
			return b.Label
		}
	}
	return AgingBuckets[len(AgingBuckets)-1].Label
}

func sortRows(rows []Row) {
	slices.SortFunc(rows, func(a, b Row) int {
		return cmp.Or(
			cmp.Compare(model.ParseSeverity(b.Severity), model.ParseSeverity(a.Severity)),
			cmp.Compare(b.AgeDays, a.AgeDays),
			cmp.Compare(a.ID, b.ID),
		)
	})
}

func meanMedian(v []float64) (float64, float64) {
	if len(v) == 0 {
		return 0, 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	var sum float64
	for _, x := range s {
		sum += x
	}
	med := s[len(s)/2]
	if len(s)%2 == 0 {
		med = (s[len(s)/2-1] + s[len(s)/2]) / 2
	}
	return round1(sum / float64(len(s))), round1(med)
}

func round1(x float64) float64 { return float64(int(x*10+0.5)) / 10 }
