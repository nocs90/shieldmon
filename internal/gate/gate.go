// Package gate decides whether an image passes a policy (docs/adr/0021-policy-gate.md). It is
// pure: the caller loads findings, decisions and evidence, and passes the time in.
package gate

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

// Verdict is the outcome of a gate.
type Verdict string

// Verdicts, from best to worst for exit codes: a fail is never hidden by missing evidence.
const (
	Pass          Verdict = "pass"
	Warn          Verdict = "warn"
	Indeterminate Verdict = "indeterminate"
	Fail          Verdict = "fail"
)

// Evidence is the scan the findings come from.
type Evidence struct {
	ScanID     int64        `json:"scan_id"`
	Status     string       `json:"status"`
	FinishedAt time.Time    `json:"finished_at"`
	Tools      []model.Tool `json:"tools,omitempty"`
	// Fresh is true when the gate ran the scan itself: its age is not checked.
	Fresh bool `json:"fresh"`
}

// Input is what a gate decides on.
type Input struct {
	Image  string
	Digest string
	// Policy names where the policy comes from (a file, the configuration), for the record.
	Policy string
	// Findings are the digest's findings as of Now, with their latest decisions
	// (report.FindingRow).
	Findings []report.Row
	// Evidence is the latest finished scan of the digest; nil when there is none.
	Evidence *Evidence
	Now      time.Time
}

// Flagged is a finding matched by rules, with the strongest of their actions.
type Flagged struct {
	report.Row
	Action string   `json:"action"`
	Rules  []string `json:"rules"`
}

// Result is a gate's verdict and what it rests on.
type Result struct {
	Image       string    `json:"image"`
	Digest      string    `json:"digest"`
	Policy      string    `json:"policy"`
	EvaluatedAt time.Time `json:"evaluated_at"`
	Verdict     Verdict   `json:"verdict"`
	ExitCode    int       `json:"exit_code"`
	// Unproven says why the evidence cannot prove a pass; with violations the verdict is
	// still fail.
	Unproven []string `json:"unproven,omitempty"`
	// Flagged are failing findings first, then warnings, highest priority first.
	Flagged []Flagged `json:"flagged"`
	// Exempt findings have a decision in force whose state the policy exempts.
	Exempt []report.Row `json:"exempt"`
	// Unflagged counts the findings no rule matches.
	Unflagged int       `json:"unflagged"`
	Evidence  *Evidence `json:"evidence,omitempty"`
}

// Evaluate applies policy p to the input. p.MaxDBAge is the DB age limit itself here (0: not
// checked); the caller resolves its default.
func Evaluate(p config.Gate, in Input) Result {
	res := Result{
		Image: in.Image, Digest: in.Digest, Policy: in.Policy, EvaluatedAt: in.Now.UTC(), Evidence: in.Evidence,
		Flagged: []Flagged{}, Exempt: []report.Row{}, Unproven: unproven(p, in),
	}
	for _, f := range in.Findings {
		st := model.State(f.State)
		if !st.Active() && !st.Suppressed() {
			continue // fixed, superseded or withdrawn: not in the image any more
		}
		if exempt(p, f, in.Now) {
			res.Exempt = append(res.Exempt, f)
			continue
		}
		fl := Flagged{Row: f}
		for _, r := range p.Rules {
			if matches(*r.When, f) {
				fl.Rules = append(fl.Rules, r.Name)
				if fl.Action != config.GateFail {
					fl.Action = r.Action
				}
			}
		}
		if fl.Action == "" {
			res.Unflagged++
			continue
		}
		res.Flagged = append(res.Flagged, fl)
	}
	slices.SortFunc(res.Flagged, func(a, b Flagged) int {
		return cmp.Or(
			cmp.Compare(rank(a.Action), rank(b.Action)),
			cmp.Compare(b.Priority, a.Priority),
			cmp.Compare(model.ParseSeverity(b.Severity), model.ParseSeverity(a.Severity)),
			cmp.Compare(a.ID, b.ID),
		)
	})
	slices.SortFunc(res.Exempt, func(a, b report.Row) int { return cmp.Compare(a.ID, b.ID) })

	switch {
	case len(res.Flagged) > 0 && res.Flagged[0].Action == config.GateFail:
		res.Verdict, res.ExitCode = Fail, p.ExitCodes.Fail
	case len(res.Unproven) > 0:
		res.Verdict, res.ExitCode = Indeterminate, p.ExitCodes.Indeterminate
	case len(res.Flagged) > 0:
		res.Verdict, res.ExitCode = Warn, p.ExitCodes.Warn
	default:
		res.Verdict = Pass
	}
	return res
}

func rank(action string) int {
	if action == config.GateFail {
		return 0
	}
	return 1
}

// matches is true when the finding meets every condition that is set.
func matches(w config.GateWhen, f report.Row) bool {
	switch {
	case w.Severity != "" && model.ParseSeverity(f.Severity) < model.ParseSeverity(w.Severity):
		return false
	case w.CVSS != nil && f.CVSS < *w.CVSS:
		return false
	case w.EPSS != nil && f.EPSS < *w.EPSS:
		return false
	case w.Priority != nil && f.Priority < *w.Priority:
		return false
	case w.AgeDays != nil && f.AgeDays < *w.AgeDays:
		return false
	case w.KEV != nil && f.KEV != *w.KEV:
		return false
	case w.Fixable != nil && (len(f.FixVersions) > 0) != *w.Fixable:
		return false
	case w.SLABreached != nil && f.SLABreached != *w.SLABreached:
		return false
	}
	return true
}

// exempt is true when the finding's state is exempt by policy and rests on a decision in
// force at now: an expired decision the monitor has not reopened yet exempts nothing.
func exempt(p config.Gate, f report.Row, now time.Time) bool {
	d := f.Decision
	if !slices.Contains(p.Exempt, f.State) || d == nil || d.State != f.State {
		return false
	}
	return d.ExpiresAt.IsZero() || now.Before(d.ExpiresAt)
}

// unproven lists why the evidence cannot prove a pass.
func unproven(p config.Gate, in Input) []string {
	ev := in.Evidence
	if ev == nil {
		return []string{"no finished scan of " + in.Digest}
	}
	var out []string
	if ev.Status != store.ScanComplete {
		out = append(out, fmt.Sprintf("scan #%d is %s: a matcher failed, findings may be missing", ev.ScanID, ev.Status))
	}
	if age := in.Now.Sub(ev.FinishedAt); !ev.Fresh && age > p.MaxEvidenceAge.Duration {
		out = append(out, fmt.Sprintf("scan #%d finished %s ago, more than max_evidence_age %s", ev.ScanID, age.Round(time.Minute), p.MaxEvidenceAge.Duration))
	}
	if p.MaxDBAge.Duration > 0 {
		for _, t := range ev.Tools {
			switch age := ev.FinishedAt.Sub(t.DBBuilt); {
			case t.DBBuilt.IsZero():
				out = append(out, t.Name+" did not report when its vulnerability DB was built")
			case age > p.MaxDBAge.Duration:
				out = append(out, fmt.Sprintf("%s matched with a vulnerability DB %s old, more than max_db_age %s", t.Name, age.Round(time.Hour), p.MaxDBAge.Duration))
			}
		}
	}
	return out
}
