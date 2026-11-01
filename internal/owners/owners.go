// Package owners says which team owns a target, from reference patterns in the configuration
// (docs/adr/0024-ownership.md).
package owners

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/oci"
)

// Unowned names targets no rule matches on the command line (--owner -).
const Unowned = "-"

const maxContact = 256

var teamName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

type rule struct {
	team, contact string
	patterns      []string
}

// Ownership maps targets to teams; the zero value owns nothing.
type Ownership struct {
	rules []rule
}

// New validates the configured owners: team names unique, patterns valid, contacts printable.
// Patterns without wildcards are normalized like image references.
func New(cfg []config.Owner) (Ownership, error) {
	var o Ownership
	seen := map[string]bool{}
	for i, c := range cfg {
		where := fmt.Sprintf("owners[%d]", i)
		if !teamName.MatchString(c.Team) {
			return o, fmt.Errorf("%s: team %q: want lowercase letters, digits, '.', '_' or '-' (at most 64)", where, c.Team)
		}
		if seen[c.Team] {
			return o, fmt.Errorf("%s: team %q listed twice", where, c.Team)
		}
		seen[c.Team] = true
		if len(c.Contact) > maxContact || strings.ContainsFunc(c.Contact, unicode.IsControl) {
			return o, fmt.Errorf("%s.contact: at most %d printable characters", where, maxContact)
		}
		if len(c.Targets) == 0 {
			return o, fmt.Errorf("%s: targets: at least one pattern", where)
		}
		r := rule{team: c.Team, contact: c.Contact}
		for _, p := range c.Targets {
			np, err := oci.RefPattern(p)
			if err != nil {
				return o, fmt.Errorf("%s.targets: %q: %w", where, p, err)
			}
			r.patterns = append(r.patterns, np)
		}
		o.rules = append(o.rules, r)
	}
	return o, nil
}

// Of returns the team owning a target reference (normalized, as targets are stored), or "".
func (o Ownership) Of(ref string) string {
	for _, r := range o.rules {
		for _, p := range r.patterns {
			if oci.MatchRef(p, ref) {
				return r.team
			}
		}
	}
	return ""
}

// OfLabel returns the team owning a target labelled "ref (platform)", as reports and events
// name them.
func (o Ownership) OfLabel(label string) string {
	ref, _, _ := strings.Cut(label, " (")
	return o.Of(ref)
}

// Teams returns the owners of these target labels, sorted, without duplicates; Unowned stands
// for labels no team owns.
func (o Ownership) Teams(labels []string) []string {
	var out []string
	for _, l := range labels {
		t := o.OfLabel(l)
		if t == "" {
			t = Unowned
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	slices.Sort(out)
	return out
}

// Contact returns a team's contact.
func (o Ownership) Contact(team string) string {
	for _, r := range o.rules {
		if r.team == team {
			return r.contact
		}
	}
	return ""
}

// Has reports whether a team is configured.
func (o Ownership) Has(team string) bool {
	return slices.ContainsFunc(o.rules, func(r rule) bool { return r.team == team })
}

// List returns the configured teams in order.
func (o Ownership) List() []string {
	out := make([]string, len(o.rules))
	for i, r := range o.rules {
		out[i] = r.team
	}
	return out
}
