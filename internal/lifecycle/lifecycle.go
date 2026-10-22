// Package lifecycle implements the finding state machine and the
// evidence-based reconciliation of a scan result against stored findings.
// It is pure: it plans changes and the store applies them atomically.
//
// Rules (docs/adr/0004-finding-lifecycle.md):
//   - fixed, superseded and withdrawn are set only by the engine and always
//     carry the scan that is the evidence. fixed and withdrawn rest on absence,
//     so they need a complete scan (every configured matcher succeeded);
//     superseded rests on presence in the successor digest.
//   - risk_accepted and not_affected require a decision with justification
//     and author; risk acceptance also requires an expiry.
//   - Humans may only move findings between open/reopened/triaged/in_remediation.
package lifecycle

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// ActorEngine is the actor recorded for automatic transitions.
const ActorEngine = "engine"

var manualTransitions = map[model.State][]model.State{
	model.StateOpen:          {model.StateTriaged, model.StateInRemediation},
	model.StateReopened:      {model.StateTriaged, model.StateInRemediation},
	model.StateTriaged:       {model.StateInRemediation, model.StateOpen},
	model.StateInRemediation: {model.StateTriaged},
}

// CheckManual validates a human-initiated transition.
func CheckManual(from, to model.State) error {
	if slices.Contains(manualTransitions[from], to) {
		return nil
	}
	switch to {
	case model.StateFixed, model.StateSuperseded, model.StateWithdrawn:
		return fmt.Errorf("%s cannot be set manually: closure requires scan evidence", to)
	case model.StateRiskAccepted, model.StateNotAffected:
		return fmt.Errorf("%s requires a decision (justification, author%s)", to,
			map[bool]string{true: ", expiry", false: ""}[to == model.StateRiskAccepted])
	}
	return fmt.Errorf("transition %s -> %s is not allowed", from, to)
}

// Deviation classifies a risk acceptance that cannot be resolved within the
// remediation deadline (documented policy deviations).
type Deviation string

const (
	// DeviationNone is a plain risk acceptance: it never outlives the SLA.
	DeviationNone Deviation = ""
	// DeviationVendorDependency: no vendor fix exists ("won't fix" or not
	// fixed yet). Re-reviewed monthly; reopened automatically when a fix ships.
	DeviationVendorDependency Deviation = "vendor_dependency"
	// DeviationOperationalRequirement: the fix exists but cannot be applied
	// for operational reasons. Long-lived, explicitly justified.
	DeviationOperationalRequirement Deviation = "operational_requirement"
)

// ParseDeviation accepts "vendor-dependency" or "vendor_dependency" style names.
func ParseDeviation(v string) (Deviation, error) {
	switch Deviation(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(v)), "-", "_")) {
	case DeviationNone:
		return DeviationNone, nil
	case DeviationVendorDependency:
		return DeviationVendorDependency, nil
	case DeviationOperationalRequirement:
		return DeviationOperationalRequirement, nil
	}
	return "", fmt.Errorf("unknown deviation %q (use vendor-dependency or operational-requirement)", v)
}

// Decision is a VEX-style statement that suppresses a finding.
type Decision struct {
	State         model.State // risk_accepted or not_affected
	Deviation     Deviation   // risk_accepted only
	Justification string
	Author        string
	ExpiresAt     time.Time
}

// Subject is the finding a decision is applied to.
type Subject struct {
	State         model.State
	Severity      model.Severity
	FirstDetected time.Time
	Fixable       bool
	FixVersions   []string
}

// Policy bounds decisions. See docs/adr/0010-decision-policy.md.
type Policy struct {
	// Profile names the SLA profile in messages (e.g. standard).
	Profile string
	// SLADays is the remediation deadline per severity, counted from first
	// detection; 0 or missing means no deadline.
	SLADays map[model.Severity]int
	// VendorDependencyMaxDays caps a vendor-dependency acceptance (monthly review).
	VendorDependencyMaxDays int
	// OperationalRequirementMaxDays caps an operational-requirement acceptance.
	OperationalRequirementMaxDays int
}

// SLADue returns the remediation deadline of a finding, or zero if none.
func (p Policy) SLADue(s Subject) time.Time {
	days := p.SLADays[s.Severity]
	if days <= 0 || s.FirstDetected.IsZero() {
		return time.Time{}
	}
	return s.FirstDetected.AddDate(0, 0, days)
}

// DefaultExpiry is the expiry used when the operator gives none: the SLA
// deadline for plain acceptances, the review period for vendor dependencies.
// Operational requirements must state their expiry explicitly.
func (p Policy) DefaultExpiry(d Decision, s Subject, now time.Time) time.Time {
	if d.State != model.StateRiskAccepted {
		return time.Time{}
	}
	switch d.Deviation {
	case DeviationNone:
		return p.SLADue(s)
	case DeviationVendorDependency:
		return now.AddDate(0, 0, p.VendorDependencyMaxDays)
	}
	return time.Time{}
}

// Validate enforces the decision requirements and the remediation policy.
func (p Policy) Validate(d Decision, s Subject, now time.Time) error {
	if d.State != model.StateRiskAccepted && d.State != model.StateNotAffected {
		return fmt.Errorf("decision state must be risk_accepted or not_affected, got %s", d.State)
	}
	if !s.State.Active() && !s.State.Suppressed() {
		return fmt.Errorf("cannot apply a decision to a %s finding", s.State)
	}
	if len(d.Justification) < 10 {
		return fmt.Errorf("justification is required (at least 10 characters)")
	}
	if d.Author == "" {
		return fmt.Errorf("author is required")
	}
	if !d.ExpiresAt.IsZero() && !d.ExpiresAt.After(now) {
		return fmt.Errorf("expiry %s is not in the future", d.ExpiresAt.Format(time.DateOnly))
	}
	if d.State == model.StateNotAffected {
		if d.Deviation != DeviationNone {
			return fmt.Errorf("not-affected is a VEX statement and takes no deviation")
		}
		return nil
	}
	if d.ExpiresAt.IsZero() {
		return fmt.Errorf("risk acceptance requires an expiry date")
	}
	day := func(t time.Time) string { return t.Format(time.DateOnly) }
	switch d.Deviation {
	case DeviationNone:
		due := p.SLADue(s)
		if due.IsZero() {
			return nil
		}
		rule := fmt.Sprintf("%s: %s findings must be remediated within %d days of first detection (%s)",
			p.Profile, s.Severity, p.SLADays[s.Severity], day(s.FirstDetected))
		if !due.After(now) {
			return fmt.Errorf("remediation deadline passed on %s (%s); a risk acceptance cannot extend it: "+
				"remediate, or record a deviation (vendor-dependency if no fix exists, operational-requirement otherwise)", day(due), rule)
		}
		if d.ExpiresAt.After(due) {
			return fmt.Errorf("expiry %s is after the remediation deadline %s (%s); "+
				"to go beyond it, record a deviation", day(d.ExpiresAt), day(due), rule)
		}
	case DeviationVendorDependency:
		if s.Fixable {
			return fmt.Errorf("a vendor fix is available (%s): vendor dependency does not apply; upgrade the package or base image",
				strings.Join(s.FixVersions, ", "))
		}
		if max := now.AddDate(0, 0, p.VendorDependencyMaxDays); d.ExpiresAt.After(max) {
			return fmt.Errorf("vendor dependencies are re-reviewed every %d days: expiry must be on or before %s",
				p.VendorDependencyMaxDays, day(max))
		}
	case DeviationOperationalRequirement:
		if len(d.Justification) < 40 {
			return fmt.Errorf("an operational requirement needs a detailed justification (at least 40 characters)")
		}
		if max := now.AddDate(0, 0, p.OperationalRequirementMaxDays); d.ExpiresAt.After(max) {
			return fmt.Errorf("operational requirements expire within %d days: expiry must be on or before %s",
				p.OperationalRequirementMaxDays, day(max))
		}
	default:
		return fmt.Errorf("unknown deviation %q", d.Deviation)
	}
	return nil
}

// Existing is a stored finding as seen by the planner.
type Existing struct {
	ID            int64
	Digest        string
	Key           string // purl|vuln
	LineageKey    string // pkgKey|vuln
	State         model.State
	FirstDetected time.Time
	// VendorDependency is true when the finding is risk-accepted under a
	// vendor-dependency deviation: it reopens as soon as a fix ships.
	VendorDependency bool
}

// Input is everything the planner needs for one scan of one digest.
type Input struct {
	Current []model.Match
	// OnDigest are all findings already stored for the scanned digest.
	OnDigest []Existing
	// Predecessors are non-terminal findings on digests this target used to
	// point to and that are no longer the current digest of any target.
	Predecessors []Existing
	// FixedLineage are lineage keys previously closed as fixed in this
	// target's history; re-detection on a new digest is a regression.
	FixedLineage map[string]bool
	// Complete is true when every configured matcher succeeded.
	Complete bool
}

// Create is a new finding row.
type Create struct {
	Match         model.Match
	State         model.State
	FirstDetected time.Time
	PredecessorID int64
	Reason        string
}

// Transition is a state change of an existing finding.
type Transition struct {
	ID     int64
	From   model.State
	To     model.State
	Reason string
}

// Plan is the set of changes produced by reconciliation.
type Plan struct {
	Creates     []Create
	Seen        map[int64]model.Match // existing findings re-observed (metadata refresh)
	Transitions []Transition
}

// Reconcile plans the changes for a scan observed at time now.
func Reconcile(in Input, now time.Time) Plan {
	p := Plan{Seen: map[int64]model.Match{}}
	onDigest := map[string]Existing{}
	for _, e := range in.OnDigest {
		onDigest[e.Key] = e
	}
	// Predecessors grouped by lineage; the earliest first-detection wins so
	// that MTTR is never understated.
	preds := map[string][]Existing{}
	for _, e := range in.Predecessors {
		if e.State.Terminal() {
			continue
		}
		preds[e.LineageKey] = append(preds[e.LineageKey], e)
	}
	for k := range preds {
		slices.SortFunc(preds[k], func(a, b Existing) int { return a.FirstDetected.Compare(b.FirstDetected) })
	}

	seenKeys := map[string]bool{}
	carried := map[string]bool{} // lineage keys present on the scanned digest
	for _, m := range in.Current {
		seenKeys[m.Key()] = true
		carried[m.LineageKey()] = true
		if e, ok := onDigest[m.Key()]; ok {
			p.Seen[e.ID] = m
			switch {
			case e.State.Terminal():
				p.Transitions = append(p.Transitions, Transition{e.ID, e.State, model.StateReopened, "detected again on the same digest"})
			case e.VendorDependency && e.State == model.StateRiskAccepted && m.Fixable():
				p.Transitions = append(p.Transitions, Transition{e.ID, e.State, model.StateReopened, vendorFixReason(m)})
			}
			continue
		}
		c := Create{Match: m, State: model.StateOpen, FirstDetected: now, Reason: "first detection"}
		if ps := preds[m.LineageKey()]; len(ps) > 0 {
			c.State, c.FirstDetected, c.PredecessorID = ps[0].State, ps[0].FirstDetected, ps[0].ID
			c.Reason = fmt.Sprintf("carried over from predecessor finding #%d", ps[0].ID)
			if ps[0].VendorDependency && c.State == model.StateRiskAccepted && m.Fixable() {
				c.State, c.Reason = model.StateReopened, c.Reason+"; "+vendorFixReason(m)
			}
		} else if in.FixedLineage[m.LineageKey()] {
			c.State, c.Reason = model.StateReopened, "regression: previously fixed in this target's history"
		}
		p.Creates = append(p.Creates, c)
	}

	// Positive evidence: the problem is still present in the successor
	// digest, so predecessors hand over to it even from a partial scan.
	for lk, ps := range preds {
		if !carried[lk] {
			continue
		}
		for _, e := range ps {
			p.Transitions = append(p.Transitions, Transition{
				e.ID, e.State, model.StateSuperseded,
				"still present in successor digest; tracking continues there",
			})
		}
	}
	// Negative evidence (absence) only counts from a complete scan.
	if in.Complete {
		for _, e := range in.OnDigest {
			if !seenKeys[e.Key] && !e.State.Terminal() {
				p.Transitions = append(p.Transitions, Transition{
					e.ID, e.State, model.StateWithdrawn,
					"no longer reported for the same digest (vulnerability data changed)",
				})
			}
		}
		for lk, ps := range preds {
			if carried[lk] {
				continue
			}
			for _, e := range ps {
				p.Transitions = append(p.Transitions, Transition{
					e.ID, e.State, model.StateFixed,
					"absent from successor digest",
				})
			}
		}
	}
	slices.SortFunc(p.Transitions, func(a, b Transition) int { return cmp.Compare(a.ID, b.ID) })
	return p
}

func vendorFixReason(m model.Match) string {
	v := strings.Join(m.FixVersions, ", ")
	if v == "" {
		v = "version not reported"
	}
	return "vendor fix now available (" + v + "): vendor-dependency acceptance no longer applies"
}
