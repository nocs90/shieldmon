package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/lineage"
)

func TestBaseProposals(t *testing.T) {
	since := day("2026-10-20")
	ts := func(ref string, b *lineage.Result) TargetSummary {
		return TargetSummary{Ref: ref, Platform: "linux/amd64", Digest: "sha256:" + ref, Base: b}
	}
	r := Monthly{
		TargetSummaries: []TargetSummary{
			ts("registry.test/current:1", &lineage.Result{BaseRef: "b:1", Status: lineage.Current}),
			ts("registry.test/stale:1", &lineage.Result{BaseRef: "b:1", Status: lineage.Current, Unmaintained: true, Successor: "b:2", SuccessorSince: since}),
			ts("registry.test/old:1", &lineage.Result{BaseRef: "b:1", Status: lineage.RebuildAvailable, Newest: "sha256:new"}),
			// Seen on python:3.12-alpine3.20: a rebuild still replaces packages, then the
			// unmaintained base must go.
			ts("registry.test/both:1", &lineage.Result{BaseRef: "b:1", Status: lineage.RebuildAvailable, Newest: "sha256:new", Unmaintained: true, Successor: "b:2"}),
			ts("registry.test/orphan:1", &lineage.Result{BaseRef: "b:1", Status: lineage.Current, Unmaintained: true}),
			ts("registry.test/wrong:1", &lineage.Result{BaseRef: "b:1", Status: lineage.Unknown}),
			ts("registry.test/none:1", &lineage.Result{Status: lineage.None}),
			{Ref: "registry.test/retired:1", Platform: "linux/amd64", RetiredAt: since, Base: &lineage.Result{Status: lineage.RebuildAvailable}},
			{Ref: "registry.test/unjudged:1", Platform: "linux/amd64"},
		},
		Open: []Row{
			{ID: 1, Remedy: "rebuild", Targets: []string{"registry.test/old:1 (linux/amd64)"}},
			{ID: 2, Remedy: "rebuild", Targets: []string{"registry.test/old:1 (linux/amd64)"}},
			{ID: 3, Remedy: "application", Targets: []string{"registry.test/old:1 (linux/amd64)", "registry.test/current:1 (linux/amd64)"}},
			{ID: 4, Remedy: "base", Targets: []string{"registry.test/stale:1 (linux/amd64)"}},
			{ID: 5, Targets: []string{"registry.test/none:1 (linux/amd64)"}},
		},
	}
	ps := BaseProposals(r)
	var got []string
	for _, p := range ps {
		got = append(got, strings.TrimSpace(p.Ref+" "+p.Action+" "+p.To+" "+p.Then+" "+p.ThenTo))
	}
	want := []string{
		"registry.test/old:1 rebuild sha256:new",
		"registry.test/both:1 rebuild sha256:new migrate b:2",
		"registry.test/stale:1 migrate b:2",
		"registry.test/orphan:1 find_base",
		"registry.test/wrong:1 verify_base",
		"registry.test/current:1 up_to_date",
		"registry.test/none:1 no_base",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("proposals:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if old := ps[0]; old.Open != 3 || old.ByRemedy["rebuild"] != 2 || old.ByRemedy["application"] != 1 {
		t.Errorf("old: %+v", old)
	}

	var md bytes.Buffer
	if err := RenderBaseProposals(&md, ps, day("2026-10-31"), "md"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"| registry.test/old:1 (linux/amd64) | b:1 | rebuild | sha256:new |  | 3 | 2 | 0 | 1 | 0 |", "b:2 (current digest since 2026-10-20)",
		"| rebuild | sha256:new | migrate to b:2 |", "Nothing is changed or pushed",
	} {
		if !strings.Contains(md.String(), s) {
			t.Errorf("markdown lacks %q:\n%s", s, md.String())
		}
	}
	var js bytes.Buffer
	if err := RenderBaseProposals(&js, ps, time.Time{}, "json"); err != nil || !json.Valid(js.Bytes()) {
		t.Errorf("json: %v", err)
	}
	if err := RenderBaseProposals(&js, ps, time.Time{}, "csv"); err == nil {
		t.Error("unknown format")
	}
}
