package lifecycle

import (
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

var (
	t0  = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now = t0.Add(72 * time.Hour)
)

func match(pkg, version, vuln string) model.Match {
	return model.Match{
		VulnID: vuln, PURL: "pkg:apk/alpine/" + pkg + "@" + version, PkgKey: "pkg:apk/alpine/" + pkg,
		PkgName: pkg, PkgVersion: version, Severity: model.SeverityHigh,
	}
}

func existing(id int64, m model.Match, st model.State) Existing {
	return Existing{ID: id, Key: m.Key(), LineageKey: m.LineageKey(), State: st, FirstDetected: t0}
}

func transitions(p Plan) map[int64]model.State {
	out := map[int64]model.State{}
	for _, t := range p.Transitions {
		out[t.ID] = t.To
	}
	return out
}

func TestFirstScanOpensFindings(t *testing.T) {
	p := Reconcile(Input{Current: []model.Match{match("busybox", "1.36.0-r9", "CVE-1")}, Complete: true}, now)
	if len(p.Creates) != 1 || p.Creates[0].State != model.StateOpen || !p.Creates[0].FirstDetected.Equal(now) {
		t.Fatalf("unexpected plan: %+v", p)
	}
}

func TestRematchKeepsStateAndRefreshes(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	p := Reconcile(Input{Current: []model.Match{m}, OnDigest: []Existing{existing(1, m, model.StateTriaged)}, Complete: true}, now)
	if len(p.Creates) != 0 || len(p.Transitions) != 0 {
		t.Fatalf("rematch must not create or transition: %+v", p)
	}
	if _, ok := p.Seen[1]; !ok {
		t.Fatal("rematch must refresh the existing finding")
	}
}

func TestDisappearanceOnSameDigestIsWithdrawnNotFixed(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	p := Reconcile(Input{OnDigest: []Existing{existing(1, m, model.StateOpen)}, Complete: true}, now)
	if got := transitions(p)[1]; got != model.StateWithdrawn {
		t.Fatalf("got %s, want withdrawn", got)
	}
}

func TestPartialScanNeverClosesByAbsence(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	old := match("zlib", "1.2.13-r1", "CVE-2")
	p := Reconcile(Input{
		OnDigest:     []Existing{existing(1, m, model.StateOpen)},
		Predecessors: []Existing{existing(2, old, model.StateOpen)},
		Complete:     false,
	}, now)
	if len(p.Transitions) != 0 {
		t.Fatalf("partial scan closed findings: %+v", p.Transitions)
	}
}

func TestSuccessorDigestFixesAbsentFindings(t *testing.T) {
	fixed := match("busybox", "1.36.0-r9", "CVE-1")
	p := Reconcile(Input{
		Current:      []model.Match{match("zlib", "1.3-r0", "CVE-9")},
		Predecessors: []Existing{existing(7, fixed, model.StateInRemediation)},
		Complete:     true,
	}, now)
	tr := p.Transitions
	if len(tr) != 1 || tr[0].ID != 7 || tr[0].To != model.StateFixed || tr[0].From != model.StateInRemediation {
		t.Fatalf("want #7 in_remediation -> fixed, got %+v", tr)
	}
}

func TestSuccessorCarriesOverAndInheritsTriage(t *testing.T) {
	old := match("busybox", "1.36.0-r9", "CVE-1")
	bumped := match("busybox", "1.36.1-r0", "CVE-1") // version changed, still vulnerable
	p := Reconcile(Input{
		Current:      []model.Match{bumped},
		Predecessors: []Existing{existing(3, old, model.StateTriaged)},
		Complete:     false, // supersession rests on presence: allowed from a partial scan
	}, now)
	if len(p.Creates) != 1 {
		t.Fatalf("want 1 create, got %+v", p.Creates)
	}
	c := p.Creates[0]
	if c.State != model.StateTriaged || c.PredecessorID != 3 || !c.FirstDetected.Equal(t0) {
		t.Errorf("successor must inherit state, predecessor and first detection: %+v", c)
	}
	if got := transitions(p)[3]; got != model.StateSuperseded {
		t.Errorf("predecessor must be superseded, got %q", got)
	}
}

func TestRegressionIsReopened(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	p := Reconcile(Input{Current: []model.Match{m}, FixedLineage: map[string]bool{m.LineageKey(): true}, Complete: true}, now)
	if len(p.Creates) != 1 || p.Creates[0].State != model.StateReopened {
		t.Fatalf("want reopened regression, got %+v", p.Creates)
	}
}

func TestTerminalRedetectionReopens(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	p := Reconcile(Input{Current: []model.Match{m}, OnDigest: []Existing{existing(1, m, model.StateWithdrawn)}, Complete: true}, now)
	if got := transitions(p)[1]; got != model.StateReopened {
		t.Fatalf("got %s, want reopened", got)
	}
}

func TestEarliestPredecessorWins(t *testing.T) {
	m := match("busybox", "1.36.0-r9", "CVE-1")
	a := existing(1, m, model.StateOpen)
	a.FirstDetected = t0.Add(24 * time.Hour)
	b := existing(2, m, model.StateTriaged)
	p := Reconcile(Input{Current: []model.Match{match("busybox", "1.37.0-r0", "CVE-1")}, Predecessors: []Existing{a, b}, Complete: true}, now)
	if p.Creates[0].PredecessorID != 2 || !p.Creates[0].FirstDetected.Equal(t0) {
		t.Errorf("must inherit the earliest detection (MTTR never understated): %+v", p.Creates[0])
	}
	tr := transitions(p)
	if tr[1] != model.StateSuperseded || tr[2] != model.StateSuperseded {
		t.Errorf("all predecessors must be superseded: %v", tr)
	}
}

func TestCheckManual(t *testing.T) {
	allowed := [][2]model.State{
		{model.StateOpen, model.StateTriaged},
		{model.StateTriaged, model.StateInRemediation},
		{model.StateReopened, model.StateInRemediation},
	}
	for _, tr := range allowed {
		if err := CheckManual(tr[0], tr[1]); err != nil {
			t.Errorf("%s -> %s: %v", tr[0], tr[1], err)
		}
	}
	denied := [][2]model.State{
		{model.StateOpen, model.StateFixed},
		{model.StateInRemediation, model.StateFixed},
		{model.StateOpen, model.StateRiskAccepted},
		{model.StateFixed, model.StateOpen},
		{model.StateOpen, model.StateWithdrawn},
	}
	for _, tr := range denied {
		if err := CheckManual(tr[0], tr[1]); err == nil {
			t.Errorf("%s -> %s must be rejected", tr[0], tr[1])
		}
	}
}

var standard = Policy{
	Profile:                       "standard",
	SLADays:                       map[model.Severity]int{model.SeverityCritical: 30, model.SeverityHigh: 30, model.SeverityMedium: 90, model.SeverityLow: 180},
	VendorDependencyMaxDays:       30,
	OperationalRequirementMaxDays: 365,
}

func TestDecisionPolicy(t *testing.T) {
	detected := now.AddDate(0, 0, -10) // high finding detected 10 days ago: SLA due in 20 days
	high := Subject{State: model.StateOpen, Severity: model.SeverityHigh, FirstDetected: detected, Fixable: true, FixVersions: []string{"1.2.4"}}
	wontFix := Subject{State: model.StateOpen, Severity: model.SeverityLow, FirstDetected: detected, FixVersions: nil}
	overdue := high
	overdue.FirstDetected = now.AddDate(0, 0, -45)
	accept := func(exp time.Time, dev Deviation, why string) Decision {
		return Decision{State: model.StateRiskAccepted, Deviation: dev, Justification: why, Author: "secops", ExpiresAt: exp}
	}
	const why = "compensating WAF rule in place, RISK-12"
	const longWhy = "patched library breaks the FIPS module; vendor validation pending, re-test quarterly"

	cases := []struct {
		name string
		d    Decision
		s    Subject
		ok   bool
	}{
		{"within SLA", accept(detected.AddDate(0, 0, 30), DeviationNone, why), high, true},
		{"beyond SLA without deviation", accept(detected.AddDate(0, 0, 31), DeviationNone, why), high, false},
		{"SLA already passed", accept(now.AddDate(0, 0, 5), DeviationNone, why), overdue, false},
		{"vendor dependency on won't-fix", accept(now.AddDate(0, 0, 30), DeviationVendorDependency, why), wontFix, true},
		{"vendor dependency longer than review period", accept(now.AddDate(0, 0, 31), DeviationVendorDependency, why), wontFix, false},
		{"vendor dependency while a fix exists", accept(now.AddDate(0, 0, 10), DeviationVendorDependency, why), high, false},
		{"operational requirement past SLA", accept(now.AddDate(0, 6, 0), DeviationOperationalRequirement, longWhy), overdue, true},
		{"operational requirement needs detail", accept(now.AddDate(0, 1, 0), DeviationOperationalRequirement, why), overdue, false},
		{"operational requirement over a year", accept(now.AddDate(1, 0, 1), DeviationOperationalRequirement, longWhy), overdue, false},
		{"no expiry", accept(time.Time{}, DeviationNone, why), high, false},
		{"past expiry", accept(now.Add(-time.Hour), DeviationNone, why), high, false},
		{"no author", Decision{State: model.StateRiskAccepted, Justification: why, ExpiresAt: now.AddDate(0, 0, 5)}, high, false},
		{"short reason", accept(now.AddDate(0, 0, 5), DeviationNone, "nope"), high, false},
		{"not affected without expiry", Decision{State: model.StateNotAffected, Justification: "vulnerable_code_not_present", Author: "a"}, overdue, true},
		{"not affected with deviation", Decision{State: model.StateNotAffected, Deviation: DeviationVendorDependency, Justification: "vulnerable_code_not_present", Author: "a"}, high, false},
		{"bad state", Decision{State: model.StateFixed, Justification: why, Author: "a"}, high, false},
		{"closed finding", accept(now.AddDate(0, 0, 5), DeviationNone, why), Subject{State: model.StateFixed}, false},
	}
	for _, tc := range cases {
		err := standard.Validate(tc.d, tc.s, now)
		if (err == nil) != tc.ok {
			t.Errorf("%s: ok=%t, err=%v", tc.name, tc.ok, err)
		}
	}
}

func TestDefaultExpiry(t *testing.T) {
	s := Subject{State: model.StateOpen, Severity: model.SeverityMedium, FirstDetected: now}
	if got := standard.DefaultExpiry(Decision{State: model.StateRiskAccepted}, s, now); !got.Equal(now.AddDate(0, 0, 90)) {
		t.Errorf("plain acceptance defaults to the SLA deadline, got %s", got)
	}
	if got := standard.DefaultExpiry(Decision{State: model.StateRiskAccepted, Deviation: DeviationVendorDependency}, s, now); !got.Equal(now.AddDate(0, 0, 30)) {
		t.Errorf("vendor dependency defaults to the review period, got %s", got)
	}
	if got := standard.DefaultExpiry(Decision{State: model.StateRiskAccepted, Deviation: DeviationOperationalRequirement}, s, now); !got.IsZero() {
		t.Error("operational requirements must state their expiry")
	}
}

func TestVendorFixReopensVendorDependency(t *testing.T) {
	m := match("libxml2", "2.9.13-6", "CVE-2025-1")
	e := existing(1, m, model.StateRiskAccepted)
	e.VendorDependency = true
	// Still no fix: nothing happens.
	if p := Reconcile(Input{Current: []model.Match{m}, OnDigest: []Existing{e}, Complete: true}, now); len(p.Transitions) != 0 {
		t.Fatalf("no fix yet: %+v", p.Transitions)
	}
	// Vendor publishes a fix: the acceptance no longer applies.
	fixed := m
	fixed.FixVersions, fixed.FixState = []string{"2.9.13-7"}, model.FixFixed
	p := Reconcile(Input{Current: []model.Match{fixed}, OnDigest: []Existing{e}, Complete: true}, now)
	if got := transitions(p)[1]; got != model.StateReopened {
		t.Fatalf("vendor fix must reopen, got %q", got)
	}
	// A plain (non-vendor) acceptance is not affected by fix availability.
	e.VendorDependency = false
	if p := Reconcile(Input{Current: []model.Match{fixed}, OnDigest: []Existing{e}, Complete: true}, now); len(p.Transitions) != 0 {
		t.Fatalf("plain acceptance must stay: %+v", p.Transitions)
	}
}

func TestParseDeviation(t *testing.T) {
	for in, want := range map[string]Deviation{"": DeviationNone, "vendor-dependency": DeviationVendorDependency, "Operational_Requirement": DeviationOperationalRequirement} {
		if got, err := ParseDeviation(in); err != nil || got != want {
			t.Errorf("ParseDeviation(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := ParseDeviation("false-positive"); err == nil {
		t.Error("unknown deviation must fail (false positives are not-affected VEX statements)")
	}
}
