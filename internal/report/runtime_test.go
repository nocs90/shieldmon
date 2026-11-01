package report

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/runtimectx"
	"github.com/nocs90/shieldmon/internal/store"
)

const (
	rtManifest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	rtIndex    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	rtOther    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

type artifacts map[string]store.Artifact

func (a artifacts) GetArtifact(_ context.Context, d string) (store.Artifact, error) {
	if x, ok := a[d]; ok {
		return x, nil
	}
	return store.Artifact{}, store.ErrNotFound
}

// The kubelet reports the index digest the image was pulled by; ShieldMon scans the
// platform manifest.
const rtInventory = `{"kind":"List","items":[
 {"kind":"Pod","metadata":{"name":"web-1","namespace":"shop","labels":{"app":"web"}},
  "status":{"phase":"Running","containerStatuses":[{"imageID":"docker.io/acme/web@` + rtIndex + `","state":{"running":{}}}]}},
 {"kind":"Service","metadata":{"name":"web","namespace":"shop"},"spec":{"type":"LoadBalancer","selector":{"app":"web"}}}]}`

func runtimeReport(now time.Time) Monthly {
	p := MonthPeriod(now)
	rows := func(digest string, ids ...int64) []Row {
		var out []Row
		for _, id := range ids {
			rw := Row{ID: id, Digest: digest, Severity: "medium", CVSS: 5, State: "open", FirstDetected: p.Start}
			rw.prioritize(now)
			out = append(out, rw)
		}
		return out
	}
	return Monthly{
		Period: p, GeneratedAt: now,
		Open:          append(rows(rtManifest, 1), rows(rtOther, 2)...),
		AcceptedRisks: rows(rtManifest, 3),
	}
}

func TestAddRuntime(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	inv, err := runtimectx.Parse([]byte(rtInventory), "prod", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	src := artifacts{rtManifest: {Digest: rtManifest, IndexDigest: rtIndex}}
	r := runtimeReport(now)
	before := r.Open[0].Priority
	failed := []runtimectx.Failure{{Cluster: "stage", Reason: "runtime inventory is stale: stage written 2026-11-01T00:00:00Z"}}
	if err := AddRuntime(context.Background(), src, &r, runtimectx.Set{inv}, failed); err != nil {
		t.Fatal(err)
	}
	web, other, accepted := r.Open[0], r.Open[1], r.AcceptedRisks[0]
	if web.Runtime == nil || !web.Runtime.Exposed || web.Priority != before+15 {
		t.Errorf("found by its index digest, running and exposed: %+v (priority %d, was %d)", web.Runtime, web.Priority, before)
	}
	if !strings.Contains(strings.Join(web.PriorityReasons, "|"), "prod: Service shop/web (LoadBalancer)") {
		t.Errorf("the reason names the exposure: %q", web.PriorityReasons)
	}
	if other.Runtime != nil || other.Priority != before {
		t.Errorf("an image running nowhere known keeps its priority: %+v", other)
	}
	if accepted.Runtime == nil {
		t.Error("risk-accepted findings get runtime context too")
	}
	if len(r.Runtime) != 2 || !r.Runtime[0].Applied || r.Runtime[0].Images != 1 || r.Runtime[1].Applied || !strings.Contains(r.Runtime[1].Reason, "stale") {
		t.Errorf("sources, a failed export included: %+v", r.Runtime)
	}
	if got := r.RuntimeTotals(); got != (RuntimeTotals{Running: 1, Exposed: 1}) {
		t.Errorf("totals: %+v", got)
	}
	if got := runtimeCell(other, r); got != "not seen in the applied exports" {
		t.Errorf("plan cell: %q", got)
	}
	if got := runtimeCell(web, r); !strings.HasPrefix(got, "running (1 pods); exposed: prod: Service") {
		t.Errorf("plan cell: %q", got)
	}

	var md, html bytes.Buffer
	if err := Render(&md, r, "md"); err != nil {
		t.Fatal(err)
	}
	if err := Render(&html, r, "html"); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"md": md.String(), "html": html.String()} {
		if !strings.Contains(out, "Runtime context") || !strings.Contains(out, "prod") || !strings.Contains(out, "is stale") {
			t.Errorf("%s report lacks the runtime context section or the export left out", name)
		}
	}
}

func TestAddRuntimeOnlyWithinThePeriod(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	// A report on October, generated in November: today's inventory says nothing about then.
	r := runtimeReport(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	r.GeneratedAt = now
	inv, err := runtimectx.Parse([]byte(rtInventory), "prod", now)
	if err != nil {
		t.Fatal(err)
	}
	before := r.Open[0].Priority
	if err := AddRuntime(context.Background(), artifacts{rtManifest: {IndexDigest: rtIndex}}, &r, runtimectx.Set{inv}, nil); err != nil {
		t.Fatal(err)
	}
	if r.Open[0].Runtime != nil || r.Open[0].Priority != before || len(r.Runtime) != 1 || r.Runtime[0].Applied {
		t.Errorf("inventory outside the period: %+v %+v", r.Open[0], r.Runtime)
	}
	if got := runtimeCell(r.Open[0], r); got != "" {
		t.Errorf("no applied inventory, empty plan cell: %q", got)
	}
	var md bytes.Buffer
	if err := Render(&md, r, "md"); err != nil || !strings.Contains(md.String(), "taken outside the period") {
		t.Errorf("the report says why the inventory was not applied: %v", err)
	}

	// Half-open periods: an export taken at the very end of October belongs to November.
	r = runtimeReport(time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC))
	r.GeneratedAt = now
	atEnd, err := runtimectx.Parse([]byte(rtInventory), "prod", r.Period.End)
	if err != nil {
		t.Fatal(err)
	}
	if err := AddRuntime(context.Background(), artifacts{}, &r, runtimectx.Set{atEnd}, nil); err != nil || r.Runtime[0].Applied {
		t.Errorf("export at the period's end: %+v, %v", r.Runtime, err)
	}
}
