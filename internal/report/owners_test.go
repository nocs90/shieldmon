package report

import (
	"slices"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/owners"
)

func TestAddOwners(t *testing.T) {
	o, err := owners.New([]config.Owner{
		{Team: "payments", Contact: "pay-sec@example.com", Targets: []string{"registry.test/app"}},
		{Team: "platform", Targets: []string{"registry.test/base*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := planFixture()
	r.TargetSummaries = []TargetSummary{
		{Ref: "registry.test/app:prod", Platform: "linux/amd64"},
		{Ref: "registry.test/other:1", Platform: "linux/amd64"},
	}
	r.Open = append(r.Open, Row{ID: 20, State: "open", Severity: "high", KEV: true, Targets: []string{"registry.test/other:1 (linux/amd64)", "registry.test/app:prod (linux/amd64)"}})
	AddOwners(&r, o)

	if r.TargetSummaries[0].Owner != "payments" || r.TargetSummaries[1].Owner != "" {
		t.Errorf("target owners: %+v", r.TargetSummaries)
	}
	if got := r.Open[2].Owners; !slices.Equal(got, []string{"-", "payments"}) {
		t.Errorf("a finding on images of several owners: %v", got)
	}
	if got := r.AcceptedRisks[0].Owners; !slices.Equal(got, []string{"-"}) {
		t.Errorf("a finding on no target is unowned: %v", got)
	}
	var teams []string
	for _, s := range r.Owners {
		teams = append(teams, s.Team)
	}
	if !slices.Equal(teams, []string{"payments", "platform", "-"}) {
		t.Fatalf("configured order, unowned last: %v", teams)
	}
	pay, unowned := r.Owners[0], r.Owners[2]
	// Open: 7 and 9 (app:prod), 20 (both).
	if pay.Open != 3 || pay.BySev["critical"] != 1 || pay.Breached != 1 || pay.KEV != 1 || pay.Targets != 1 || pay.Contact != "pay-sec@example.com" {
		t.Errorf("payments: %+v", pay)
	}
	if unowned.Open != 1 || unowned.Targets != 1 || r.Owners[1].Open != 0 {
		t.Errorf("unowned %+v, platform %+v", unowned, r.Owners[1])
	}
	if cell := ownerCell(r.Open[2], r); cell != "unowned; payments <pay-sec@example.com>" {
		t.Errorf("plan cell %q", cell)
	}

	plain := planFixture()
	AddOwners(&plain, owners.Ownership{})
	if plain.Owners != nil || plain.Open[0].Owners != nil {
		t.Error("without configured owners nothing is added")
	}
	var b strings.Builder
	err = renderMarkdown(&b, r)
	if err != nil || !strings.Contains(b.String(), "| payments | pay-sec@example.com | 1 | 3 | 1 | 2 | 1 | 1 |") {
		t.Errorf("markdown by owner (%v):\n%s", err, b.String())
	}
}
