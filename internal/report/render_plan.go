package report

import (
	"cmp"
	"encoding/csv"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() {
	RegisterFormat(Format{
		Name:        "remediation-plan",
		Description: "remediation plan: one row per open or risk-accepted item, with schedule, milestones and deviation (CSV)",
		Render:      func(w io.Writer, r Monthly) error { return renderPlan(w, r, false) },
	})
	RegisterFormat(Format{
		Name:        "remediation-plan-excel",
		Description: "remediation-plan for spreadsheets: UTF-8 with BOM, CRLF line endings",
		Render:      func(w io.Writer, r Monthly) error { return renderPlan(w, r, true) },
	})
}

// planHeader is the remediation plan worksheet: what auditors and compliance teams track for
// each open vulnerability.
var planHeader = []string{
	"item_id", "status", "weakness", "aliases", "weakness_description", "severity", "cvss", "epss", "kev",
	"asset", "digest", "package", "installed_version", "purl", "detected", "age_days",
	"sla_due", "sla_breached", "scheduled_completion", "milestones", "fix_available", "fixed_versions",
	"deviation", "decision", "decision_author", "decision_justification", "decision_expires", "priority", "remedy", "owner",
}

// renderPlan writes the plan. excel adds a UTF-8 BOM and CRLF line endings, so that
// spreadsheet applications open non-ASCII package names correctly.
func renderPlan(w io.Writer, r Monthly, excel bool) error {
	if excel {
		if _, err := io.WriteString(w, "\uFEFF"); err != nil {
			return err
		}
	}
	cw := csv.NewWriter(w)
	cw.UseCRLF = excel
	if err := cw.Write(planHeader); err != nil {
		return err
	}
	// Open and risk-accepted items; a not_affected finding is no weakness to remediate.
	rows := slices.Concat(r.Open, slices.DeleteFunc(slices.Clone(r.AcceptedRisks), func(x Row) bool { return x.State != "risk_accepted" }))
	// Soonest scheduled completion first; items without a date last.
	slices.SortStableFunc(rows, func(a, b Row) int {
		ca, cb := scheduledCompletion(a), scheduledCompletion(b)
		switch {
		case ca.IsZero() != cb.IsZero():
			if ca.IsZero() {
				return 1
			}
			return -1
		case !ca.Equal(cb):
			return ca.Compare(cb)
		}
		return cmp.Compare(a.ID, b.ID)
	})
	for _, x := range rows {
		d := x.Decision
		if d == nil {
			d = &DecisionInfo{}
		}
		rec := []string{
			strconv.FormatInt(x.ID, 10), x.State, x.VulnID, strings.Join(x.Aliases, " "), oneLine(x.Title), x.Severity,
			strconv.FormatFloat(x.CVSS, 'f', 1, 64), strconv.FormatFloat(x.EPSS, 'f', 5, 64), strconv.FormatBool(x.KEV),
			strings.Join(x.Targets, "; "), x.Digest, x.Package, x.Version, x.PURL,
			dateOrEmpty(x.FirstDetected), strconv.Itoa(x.AgeDays),
			dateOrEmpty(x.SLADue), strconv.FormatBool(x.SLABreached), dateOrEmpty(scheduledCompletion(x)), milestones(x),
			fixAvailable(x), strings.Join(x.FixVersions, " "),
			deviation(x), d.State, oneLine(d.Author), oneLine(d.Justification), dateOrEmpty(d.ExpiresAt),
			strconv.Itoa(x.Priority), x.Remedy, oneLine(ownerCell(x, r)),
		}
		for i, v := range rec {
			rec[i] = CSVSafe(v)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// scheduledCompletion is when the item is planned to be done: the remediation deadline, or
// for a risk acceptance its expiry (the date it must be fixed or decided again).
func scheduledCompletion(x Row) time.Time {
	if x.State == "risk_accepted" && x.Decision != nil && !x.Decision.ExpiresAt.IsZero() {
		return x.Decision.ExpiresAt
	}
	return x.SLADue
}

// deviation names why an item may outlive its deadline: none for open items.
func deviation(x Row) string {
	if x.State != "risk_accepted" || x.Decision == nil {
		return ""
	}
	if x.Decision.Deviation == "" {
		return "risk_acceptance"
	}
	return x.Decision.Deviation
}

func fixAvailable(x Row) string {
	switch {
	case len(x.FixVersions) > 0:
		return "yes"
	case x.FixState == "wont_fix":
		return "wont_fix"
	}
	return "no"
}

// milestones are the dated steps of the item in date order, then the action that completes
// it when a fix exists.
func milestones(x Row) string {
	type step struct {
		at   time.Time
		what string
	}
	steps := []step{{x.FirstDetected, "detected"}}
	if !x.SLADue.IsZero() {
		what := "remediation due"
		if x.SLABreached {
			what = "remediation was due (breached)"
		}
		steps = append(steps, step{x.SLADue, what})
	}
	if d := x.Decision; d != nil && x.State == "risk_accepted" && !d.ExpiresAt.IsZero() {
		what := "risk acceptance expires"
		switch d.Deviation {
		case "vendor_dependency":
			what = "vendor dependency review"
		case "operational_requirement":
			what = "operational requirement expires"
		}
		steps = append(steps, step{d.ExpiresAt, what})
	}
	slices.SortStableFunc(steps, func(a, b step) int { return a.at.Compare(b.at) })
	out := make([]string, 0, len(steps)+1)
	for _, s := range steps {
		out = append(out, dateOrEmpty(s.at)+" "+s.what)
	}
	if len(x.FixVersions) > 0 {
		out = append(out, fmt.Sprintf("upgrade %s to %s", x.Package, strings.Join(x.FixVersions, " or ")))
	}
	return oneLine(strings.Join(out, "; "))
}

// oneLine keeps a cell on one line: spreadsheets and line-based tools split on breaks.
func oneLine(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }), " ")
}
