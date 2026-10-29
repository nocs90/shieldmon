package gate

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

var now = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func complete() *Evidence {
	return &Evidence{
		ScanID: 1, Status: store.ScanComplete, FinishedAt: now.Add(-time.Hour),
		Tools: []model.Tool{{Name: "grype", DBBuilt: now.Add(-30 * time.Hour)}, {Name: "trivy", DBBuilt: now.Add(-20 * time.Hour)}},
	}
}

func policy() config.Gate {
	p := config.DefaultGate()
	p.MaxDBAge = config.Duration{Duration: 72 * time.Hour}
	return p
}

func evaluate(p config.Gate, ev *Evidence, rows ...report.Row) Result {
	return Evaluate(p, Input{Image: "registry.test/app:1", Digest: "sha256:aaaa", Findings: rows, Evidence: ev, Now: now})
}

func ids(fs []Flagged) []int64 {
	var out []int64
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestDefaultPolicy(t *testing.T) {
	rows := []report.Row{
		{ID: 1, State: "open", Severity: "low"},
		{ID: 2, State: "triaged", Severity: "high", Priority: 40},
		{ID: 3, State: "open", Severity: "high", KEV: true, Priority: 80},
		{ID: 4, State: "in_remediation", Severity: "critical", Priority: 50},
		{ID: 5, State: "reopened", Severity: "medium", SLABreached: true, Priority: 30},
		{ID: 6, State: "fixed", Severity: "critical"},
		{ID: 7, State: "superseded", Severity: "critical", KEV: true},
	}
	r := evaluate(policy(), complete(), rows...)
	if r.Verdict != Fail || r.ExitCode != 2 {
		t.Fatalf("verdict = %s (%d)", r.Verdict, r.ExitCode)
	}
	if got := ids(r.Flagged); !slices.Equal(got, []int64{3, 4, 5, 2}) {
		t.Errorf("flagged = %v: failures by priority, then warnings; closed findings are not in the image", got)
	}
	if f := r.Flagged[0]; f.Action != config.GateFail || !slices.Equal(f.Rules, []string{"exploited", "high"}) {
		t.Errorf("strongest action wins, every matching rule is listed: %+v", f)
	}
	if r.Unflagged != 1 || len(r.Unproven) != 0 {
		t.Errorf("unflagged = %d, unproven = %v", r.Unflagged, r.Unproven)
	}

	r = evaluate(policy(), complete(), rows[:2]...)
	if r.Verdict != Warn || r.ExitCode != 0 {
		t.Errorf("only a high finding: %s (%d)", r.Verdict, r.ExitCode)
	}
	p := policy()
	p.ExitCodes.Warn = 4
	if r := evaluate(p, complete(), rows[:2]...); r.ExitCode != 4 {
		t.Errorf("warn exit code is configurable: %d", r.ExitCode)
	}
	if r := evaluate(policy(), complete(), rows[0], rows[5]); r.Verdict != Pass || r.ExitCode != 0 {
		t.Errorf("pass: %+v", r)
	}
}

func TestConditions(t *testing.T) {
	f := report.Row{
		ID: 1, State: "open", Severity: "high", CVSS: 7.5, EPSS: 0.2, Priority: 55, AgeDays: 40,
		FixVersions: []string{"1.2"}, SLABreached: true,
	}
	for _, c := range []struct {
		name string
		when config.GateWhen
		want bool
	}{
		{"empty", config.GateWhen{}, true},
		{"severity at least", config.GateWhen{Severity: "medium"}, true},
		{"severity above", config.GateWhen{Severity: "critical"}, false},
		{"cvss inclusive", config.GateWhen{CVSS: ptr(7.5)}, true},
		{"cvss above", config.GateWhen{CVSS: ptr(7.6)}, false},
		{"epss", config.GateWhen{EPSS: ptr(0.1)}, true},
		{"epss above", config.GateWhen{EPSS: ptr(0.5)}, false},
		{"priority", config.GateWhen{Priority: ptr(55)}, true},
		{"priority above", config.GateWhen{Priority: ptr(56)}, false},
		{"age", config.GateWhen{AgeDays: ptr(30)}, true},
		{"age above", config.GateWhen{AgeDays: ptr(41)}, false},
		{"not kev", config.GateWhen{KEV: ptr(false)}, true},
		{"kev", config.GateWhen{KEV: ptr(true)}, false},
		{"fixable", config.GateWhen{Fixable: ptr(true)}, true},
		{"not fixable", config.GateWhen{Fixable: ptr(false)}, false},
		{"breached", config.GateWhen{SLABreached: ptr(true)}, true},
		{"all must hold", config.GateWhen{Severity: "high", Fixable: ptr(true), KEV: ptr(true)}, false},
	} {
		if got := matches(c.when, f); got != c.want {
			t.Errorf("%s: matches = %v", c.name, got)
		}
	}
	if matches(config.GateWhen{Severity: "negligible"}, report.Row{Severity: "unknown"}) {
		t.Error("an unknown severity meets no severity condition")
	}
}

func TestExemptOnlyByDecisionInForce(t *testing.T) {
	accepted := report.Row{
		ID: 1, State: "risk_accepted", Severity: "critical",
		Decision: &report.DecisionInfo{State: "risk_accepted", Author: "lead", Justification: "no fix yet", ExpiresAt: now.Add(time.Hour)},
	}
	notAffected := report.Row{
		ID: 2, State: "not_affected", Severity: "critical", KEV: true,
		Decision: &report.DecisionInfo{State: "not_affected", Author: "vendor", Justification: "vulnerable_code_not_present"},
	}
	r := evaluate(policy(), complete(), accepted, notAffected)
	if r.Verdict != Pass || len(r.Exempt) != 2 {
		t.Fatalf("decisions in force exempt: %s, exempt %d", r.Verdict, len(r.Exempt))
	}

	expired := accepted
	expired.Decision = &report.DecisionInfo{State: "risk_accepted", ExpiresAt: now}
	if r := evaluate(policy(), complete(), expired); r.Verdict != Fail || len(r.Exempt) != 0 {
		t.Errorf("an expired acceptance not reopened yet exempts nothing: %s", r.Verdict)
	}
	orphan := notAffected
	orphan.Decision = nil
	if r := evaluate(policy(), complete(), orphan); r.Verdict != Fail {
		t.Errorf("a suppressed state without its decision exempts nothing: %s", r.Verdict)
	}
	p := policy()
	p.Exempt = []string{"not_affected"}
	r = evaluate(p, complete(), accepted, notAffected)
	if r.Verdict != Fail || len(r.Exempt) != 1 || r.Flagged[0].ID != 1 {
		t.Errorf("only listed decision states exempt: %s %v", r.Verdict, ids(r.Flagged))
	}
}

func TestFailClosed(t *testing.T) {
	high := report.Row{ID: 1, State: "open", Severity: "high"}
	crit := report.Row{ID: 2, State: "open", Severity: "critical"}
	at := func(f func(*Evidence)) *Evidence {
		ev := complete()
		f(ev)
		return ev
	}
	for _, c := range []struct {
		name string
		ev   *Evidence
		p    func(*config.Gate)
		want string
	}{
		{"no scan", nil, nil, "no finished scan"},
		{"partial", at(func(e *Evidence) { e.Status = store.ScanPartial }), nil, "is partial"},
		{"failed", at(func(e *Evidence) { e.Status = store.ScanFailed; e.Tools = nil }), nil, "is failed"},
		{"stale evidence", at(func(e *Evidence) { e.FinishedAt = now.Add(-25 * time.Hour) }), nil, "max_evidence_age"},
		{"stale db", at(func(e *Evidence) { e.Tools[1].DBBuilt = now.Add(-100 * time.Hour) }), nil, "trivy matched with a vulnerability DB"},
		{"unknown db age", at(func(e *Evidence) { e.Tools[0].DBBuilt = time.Time{} }), nil, "grype did not report"},
	} {
		p := policy()
		if c.p != nil {
			c.p(&p)
		}
		r := evaluate(p, c.ev, high)
		if r.Verdict != Indeterminate || r.ExitCode != 3 || !strings.Contains(strings.Join(r.Unproven, "|"), c.want) {
			t.Errorf("%s: %s (%d) %v", c.name, r.Verdict, r.ExitCode, r.Unproven)
		}
		if r := evaluate(p, c.ev, high, crit); r.Verdict != Fail || len(r.Unproven) == 0 {
			t.Errorf("%s: violations seen in incomplete evidence fail: %s", c.name, r.Verdict)
		}
	}

	fresh := complete()
	fresh.FinishedAt, fresh.Fresh = now.Add(-48*time.Hour), true
	if r := evaluate(policy(), fresh); r.Verdict != Pass {
		t.Errorf("the gate's own scan is not aged: %v", r.Unproven)
	}
	p := policy()
	p.MaxDBAge.Duration = 0
	old := complete()
	old.Tools[0].DBBuilt = time.Time{}
	if r := evaluate(p, old); r.Verdict != Pass {
		t.Errorf("max_db_age 0 does not check DB age: %v", r.Unproven)
	}
}

func TestSARIF(t *testing.T) {
	r := evaluate(policy(), complete(),
		report.Row{ID: 1, State: "open", Severity: "critical", VulnID: "CVE-2026-1", Package: "openssl", Version: "3.0", PURL: "pkg:apk/alpine/openssl@3.0", Targets: []string{"registry.test/app:1 (linux/amd64)"}},
		report.Row{ID: 2, State: "open", Severity: "high", VulnID: "CVE-2026-2", Package: "<b>x</b>", Version: "1"},
		report.Row{ID: 3, State: "open", Severity: "low", VulnID: "CVE-2026-3", Package: "zlib", Version: "1"},
		report.Row{
			ID: 4, State: "risk_accepted", Severity: "critical", VulnID: "CVE-2026-4", Package: "busybox", Version: "1",
			Decision: &report.DecisionInfo{State: "risk_accepted", Deviation: "vendor_dependency", Author: "lead", Justification: "no fix", ExpiresAt: now.Add(time.Hour)},
		},
	)
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("../report/testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	schema, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("sarif.json", schema); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("sarif.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("not valid SARIF 2.1.0: %v", err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID       string
				Level        string
				Suppressions []struct{ Justification string }
				Properties   map[string]any
			}
			Properties map[string]string
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	var got []string
	for _, res := range run.Results {
		s := res.RuleID + ":" + res.Level
		if len(res.Suppressions) > 0 {
			s += ":suppressed:" + res.Suppressions[0].Justification
		}
		got = append(got, s)
	}
	want := []string{"CVE-2026-1:error", "CVE-2026-2:warning", "CVE-2026-4:error:suppressed:risk_accepted (vendor_dependency): no fix"}
	if !slices.Equal(got, want) {
		t.Errorf("results = %v, want %v (unflagged findings are no result)", got, want)
	}
	if run.Properties["gate_verdict"] != "fail" || run.Properties["digest"] != "sha256:aaaa" {
		t.Errorf("run properties = %v", run.Properties)
	}
	if strings.Contains(buf.String(), "<b>") {
		t.Error("hostile package names are JSON-escaped")
	}
}
