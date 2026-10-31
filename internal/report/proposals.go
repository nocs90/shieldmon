package report

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
)

// Base actions: what a target's owners can do about its base (docs/processes/base-images.md).
const (
	ActionRebuild   = "rebuild"     // a newer digest of the base tag exists
	ActionMigrate   = "migrate"     // the base is unmaintained; a successor is configured
	ActionFindBase  = "find_base"   // the base is unmaintained; no successor is configured
	ActionVerify    = "verify_base" // the configured or annotated base shares no layers
	ActionUpToDate  = "up_to_date"  // on the newest, maintained base
	ActionNoBase    = "no_base"     // no base configured or annotated
	maxProposalRows = 10_000
)

// BaseProposal is what to do about one target's base, with the open findings a rebuild would
// replace and those it would not: the before and after of the change (it is never made here).
type BaseProposal struct {
	Ref      string         `json:"ref"`
	Platform string         `json:"platform"`
	Digest   string         `json:"digest"`
	Base     lineage.Result `json:"base"`
	Action   string         `json:"action"`
	// To is what to rebuild on or move to: the newest base digest, or the successor tag.
	To string `json:"to,omitempty"`
	// Then is the next step after a rebuild on an unmaintained base: migrate or find_base,
	// with ThenTo the successor.
	Then   string `json:"then,omitempty"`
	ThenTo string `json:"then_to,omitempty"`
	// Open counts the target's open findings; ByRemedy splits them (ADR 0023).
	Open     int            `json:"open"`
	ByRemedy map[string]int `json:"open_by_remedy"`
}

// BaseProposals lists, for each monitored target with its lineage (AddBaseLineage with an
// SBOM reader), the base action and its finding counts: rebuilds first, then migrations.
func BaseProposals(r Monthly) []BaseProposal {
	var out []BaseProposal
	for _, ts := range r.TargetSummaries {
		if ts.Base == nil || !ts.RetiredAt.IsZero() {
			continue
		}
		p := BaseProposal{Ref: ts.Ref, Platform: ts.Platform, Digest: ts.Digest, Base: *ts.Base, ByRemedy: map[string]int{}}
		label := ts.Ref + " (" + ts.Platform + ")"
		for _, x := range r.Open {
			if slices.Contains(x.Targets, label) {
				p.Open++
				if x.Remedy != "" {
					p.ByRemedy[x.Remedy]++
				}
			}
		}
		b := p.Base
		// Moving off an unmaintained base, when it is: to the successor, or to be found.
		migrate, to := "", ""
		if b.Unmaintained {
			migrate, to = ActionFindBase, ""
			if b.Successor != "" {
				migrate, to = ActionMigrate, b.Successor
			}
		}
		switch {
		case b.Status == lineage.None:
			p.Action = ActionNoBase
		case b.Status == lineage.Unknown:
			p.Action = ActionVerify
		case b.Status == lineage.RebuildAvailable:
			// A rebuild replaces packages now, even on an unmaintained base; moving comes next.
			p.Action, p.To, p.Then, p.ThenTo = ActionRebuild, b.Newest, migrate, to
		case migrate != "":
			p.Action, p.To = migrate, to
		default:
			p.Action = ActionUpToDate
		}
		out = append(out, p)
		if len(out) == maxProposalRows {
			break
		}
	}
	rank := map[string]int{ActionRebuild: 0, ActionMigrate: 1, ActionFindBase: 2, ActionVerify: 3, ActionUpToDate: 4, ActionNoBase: 5}
	slices.SortStableFunc(out, func(a, b BaseProposal) int {
		return cmp.Or(cmp.Compare(rank[a.Action], rank[b.Action]),
			cmp.Compare(b.ByRemedy[string(lineage.RemedyRebuild)], a.ByRemedy[string(lineage.RemedyRebuild)]),
			cmp.Compare(a.Ref+" "+a.Platform, b.Ref+" "+b.Platform))
	})
	return out
}

// RenderBaseProposals writes the proposals as md (default) or json.
func RenderBaseProposals(w io.Writer, ps []BaseProposal, asOf time.Time, format string) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			AsOf      time.Time      `json:"as_of"`
			Proposals []BaseProposal `json:"proposals"`
		}{asOf.UTC(), ps})
	}
	if format != "md" {
		return fmt.Errorf("format %q: want md or json", format)
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "# Base image proposals\n\nAs of %s. Nothing is changed or pushed: these are the rebuilds and migrations to make (docs/processes/base-images.md).\n\n", asOf.UTC().Format(time.RFC3339))
	if len(ps) == 0 {
		b.WriteString("_No monitored image has a known base: `shieldmon targets set-base`._\n")
	} else {
		b.WriteString("| Target | Base | Action | To | Then | Open | Rebuild replaces | Same in newest base | Application | Unknown |\n|---|---|---|---|---|---:|---:|---:|---:|---:|\n")
		successor := func(p BaseProposal, s string) string {
			if s != "" && !p.Base.SuccessorSince.IsZero() {
				s += " (current digest since " + p.Base.SuccessorSince.UTC().Format(time.DateOnly) + ")"
			}
			return s
		}
		for _, p := range ps {
			to := p.To
			if p.Action == ActionMigrate {
				to = successor(p, to)
			}
			then := strings.ReplaceAll(p.Then, "_", " ")
			if p.ThenTo != "" {
				then += " to " + successor(p, p.ThenTo)
			}
			fmt.Fprintf(b, "| %s (%s) | %s | %s | %s | %s | %d | %d | %d | %d | %d |\n", mdEscape(p.Ref), mdEscape(p.Platform), mdEscape(p.Base.BaseRef),
				strings.ReplaceAll(p.Action, "_", " "), mdEscape(to), mdEscape(then), p.Open, p.ByRemedy[string(lineage.RemedyRebuild)],
				p.ByRemedy[string(lineage.RemedyBase)], p.ByRemedy[string(lineage.RemedyApplication)], p.ByRemedy[string(lineage.RemedyUnknown)])
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}
