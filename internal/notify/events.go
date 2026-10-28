package notify

import (
	"fmt"
	"time"
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
//   - health_opened: per health finding and opening.
func Collect(in Input) []Event {
	var out []Event
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
	Sort(out)
	return out
}

func healthKey(h Health) string {
	return fmt.Sprintf("health:%s:%s:%s", h.Check, h.Subject, h.FirstSeen.UTC().Format(time.RFC3339Nano))
}

// Current keeps the pending events that still describe the state, with their finding
// refreshed (targets, state, fix versions may have changed since the event was recorded):
// a finding event while its lineage is active, a health event while that health finding is
// still open since the same time. The rest would be stale news.
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
	var out []Event
	for _, e := range pending {
		switch {
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
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}
