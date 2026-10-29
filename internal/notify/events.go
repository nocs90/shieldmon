package notify

import (
	"fmt"
	"slices"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
)

// Input is the monitoring state events are computed from. Computing them is pure: the
// engine reads the store, Collect decides.
type Input struct {
	Now time.Time
	// Since is when the previous monitoring cycle began: findings created after it are new.
	Since time.Time
	// DueSoon is how long before its remediation deadline a finding is due soon.
	DueSoon time.Duration
	// Active are the findings that still need remediation work.
	Active []Active
	// Health are the open health findings.
	Health []Health
	// Fixed are findings closed as fixed, with the targets of the scan that gave the evidence.
	Fixed []Fixed
	// Bases are the base lineages of the monitored image digests with a known base.
	Bases []Base
}

// Fixed is a finding closed as fixed by scan evidence.
type Fixed struct {
	Finding
	Lineage  int64
	ClosedAt time.Time
}

// Active is an active finding with its place in its lineage (the same problem followed across
// digests of a target).
type Active struct {
	Finding
	// Lineage is the ID of the first finding of the lineage.
	Lineage   int64
	CreatedAt time.Time
	// Carried is true when the finding continues a predecessor's problem: not new.
	Carried bool
}

// Collect returns the events the state warrants. Keys make them idempotent: collecting again
// in a later cycle gives the same keys for the same facts.
//   - finding_new_kev, finding_new_critical: a finding created since the previous cycle,
//     not carried over, in CISA KEV or critical (KEV wins: one event per finding);
//   - sla_breached, sla_due_soon: per lineage and deadline;
//   - health_opened: per health finding and opening;
//   - finding_fixed: a finding closed as fixed since the previous cycle began (none in the
//     first cycle, which reports the state rather than history).
func Collect(in Input) []Event {
	var out []Event
	for _, x := range in.Fixed {
		if in.Since.IsZero() || x.ClosedAt.Before(in.Since) {
			continue
		}
		f := x.Finding
		f.Lineage = x.Lineage
		out = append(out, Event{Key: fmt.Sprintf("finding_fixed:%d", f.ID), Kind: FindingFixed, Finding: &f, Remaining: remaining(f, in.Active)})
	}
	for _, a := range in.Active {
		f := a.Finding
		f.Lineage = a.Lineage
		if !a.Carried && !a.CreatedAt.Before(in.Since) {
			switch {
			case f.KEV:
				out = append(out, Event{Key: fmt.Sprintf("finding_new:%d", f.ID), Kind: FindingNewKEV, Finding: &f})
			case f.Severity == "critical":
				out = append(out, Event{Key: fmt.Sprintf("finding_new:%d", f.ID), Kind: FindingNewCritical, Finding: &f})
			}
		}
		if due := f.SLADue; !due.IsZero() {
			sla := fmt.Sprintf("%d:%s", a.Lineage, due.UTC().Format(time.RFC3339))
			switch {
			case !in.Now.Before(due):
				out = append(out, Event{Key: "sla_breached:" + sla, Kind: SLABreached, Finding: &f})
			case in.DueSoon > 0 && due.Sub(in.Now) <= in.DueSoon:
				out = append(out, Event{Key: "sla_due_soon:" + sla, Kind: SLADueSoon, Finding: &f})
			}
		}
	}
	for _, h := range in.Health {
		out = append(out, Event{Key: healthKey(h), Kind: HealthOpened, Health: &h})
	}
	out = append(out, baseEvents(in.Bases)...)
	Sort(out)
	return out
}

// baseEvents are base_rebuild_available and base_unmaintained, once per image digest and
// newest base digest: a later base move or rebuild is new news.
func baseEvents(bases []Base) []Event {
	var out []Event
	for _, b := range bases {
		if b.Status == string(lineage.RebuildAvailable) {
			out = append(out, Event{Key: "base_rebuild_available:" + b.Digest + ":" + b.Newest, Kind: BaseRebuildAvailable, Base: &b})
		}
		if b.Unmaintained {
			out = append(out, Event{Key: "base_unmaintained:" + b.Digest + ":" + b.Newest, Kind: BaseUnmaintained, Base: &b})
		}
	}
	return out
}

func healthKey(h Health) string {
	return fmt.Sprintf("health:%s:%s:%s", h.Check, h.Subject, h.FirstSeen.UTC().Format(time.RFC3339Nano))
}

// remaining counts the active findings with f's vulnerability on one of f's targets.
func remaining(f Finding, active []Active) int {
	n := 0
	for _, a := range active {
		if a.VulnID == f.VulnID && slices.ContainsFunc(a.Targets, func(t string) bool { return slices.Contains(f.Targets, t) }) {
			n++
		}
	}
	return n
}

// Current keeps the pending events that still describe the state, with their finding
// refreshed (targets, state, fix versions may have changed since the event was recorded):
// a finding event while its lineage is active, a health event while that health finding is
// still open since the same time, a base event while it still holds. The rest would be stale
// news.
func Current(pending []Event, in Input) []Event {
	lineages := map[int64]Finding{}
	for _, a := range in.Active {
		f := a.Finding
		f.Lineage = a.Lineage
		lineages[a.Lineage] = f
	}
	open := map[string]bool{}
	for _, h := range in.Health {
		open[healthKey(h)] = true
	}
	bases := map[string]*Base{}
	for _, e := range baseEvents(in.Bases) {
		bases[e.Key] = e.Base
	}
	var out []Event
	for _, e := range pending {
		switch {
		case e.Kind == FindingFixed && e.Finding != nil:
			if _, reopened := lineages[e.Finding.Lineage]; reopened {
				continue
			}
			e.Remaining = remaining(*e.Finding, in.Active)
		case e.Finding != nil:
			f, ok := lineages[e.Finding.Lineage]
			if !ok {
				continue
			}
			if e.Kind == SLABreached || e.Kind == SLADueSoon {
				f.SLADue = e.Finding.SLADue // the deadline the event is about
			}
			e.Finding = &f
		case e.Health != nil:
			if !open[e.Key] {
				continue
			}
		case e.Base != nil:
			b, ok := bases[e.Key]
			if !ok {
				continue
			}
			e.Base = b // the images on the digest may have changed
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}
