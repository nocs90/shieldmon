package report

import (
	"cmp"
	"slices"
	"strings"

	"github.com/nocs90/shieldmon/internal/owners"
)

// OwnerSummary is the open-finding picture of one team (docs/adr/0024-ownership.md); the team
// "-" stands for findings and targets no team owns.
type OwnerSummary struct {
	Team     string         `json:"team"`
	Contact  string         `json:"contact,omitempty"`
	Targets  int            `json:"targets"`
	Open     int            `json:"open"`
	BySev    map[string]int `json:"open_by_severity"`
	Breached int            `json:"sla_breaches"`
	KEV      int            `json:"kev_open"`
}

// AddOwners sets the owners of the report's rows and targets and sums open findings per team,
// with the ownership configured now. Nothing is added without configured owners.
func AddOwners(r *Monthly, o owners.Ownership) {
	teams := o.List()
	if len(teams) == 0 {
		return
	}
	byTeam := map[string]*OwnerSummary{}
	summary := func(team string) *OwnerSummary {
		s, ok := byTeam[team]
		if !ok {
			s = &OwnerSummary{Team: team, Contact: o.Contact(team), BySev: map[string]int{}}
			byTeam[team] = s
		}
		return s
	}
	for _, team := range teams {
		summary(team)
	}
	for i := range r.TargetSummaries {
		ts := &r.TargetSummaries[i]
		ts.Owner = o.Of(ts.Ref)
		if ts.RetiredAt.IsZero() {
			summary(teamOr(ts.Owner)).Targets++
		}
	}
	for _, rows := range [][]Row{r.Open, r.AcceptedRisks, r.FixedInPeriod, r.RetiredWithAsset} {
		for i := range rows {
			rows[i].Owners = o.Teams(rows[i].Targets)
			if len(rows[i].Owners) == 0 {
				rows[i].Owners = []string{owners.Unowned}
			}
		}
	}
	for _, x := range r.Open {
		for _, team := range x.Owners {
			s := summary(team)
			s.Open++
			s.BySev[x.Severity]++
			if x.SLABreached {
				s.Breached++
			}
			if x.KEV {
				s.KEV++
			}
		}
	}
	r.Owners = nil
	for _, s := range byTeam {
		r.Owners = append(r.Owners, *s)
	}
	// Configured order; unowned last.
	slices.SortFunc(r.Owners, func(a, b OwnerSummary) int {
		return cmp.Compare(teamIndex(teams, a.Team), teamIndex(teams, b.Team))
	})
}

func teamOr(team string) string {
	if team == "" {
		return owners.Unowned
	}
	return team
}

func teamIndex(teams []string, team string) int {
	if i := slices.Index(teams, team); i >= 0 {
		return i
	}
	return len(teams)
}

// ownerCell is the remediation plan's point of contact: each owning team with its contact.
func ownerCell(x Row, r Monthly) string {
	var out []string
	for _, team := range x.Owners {
		if team == owners.Unowned {
			out = append(out, "unowned")
			continue
		}
		for _, s := range r.Owners {
			if s.Team == team && s.Contact != "" {
				team += " <" + s.Contact + ">"
			}
		}
		out = append(out, team)
	}
	return strings.Join(out, "; ")
}
