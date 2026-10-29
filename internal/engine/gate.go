package engine

import (
	"context"
	"errors"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/gate"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/store"
)

// GateDigest evaluates the findings of a digest against gate policy p, on the latest finished
// scan of the digest (docs/adr/0021-policy-gate.md). scanID is the scan the caller has just
// run (0: none), whose age is not checked; source names the policy for the record. The gate
// changes nothing.
func (e *Engine) GateDigest(ctx context.Context, image, digest string, p config.Gate, source string, scanID int64) (gate.Result, error) {
	if p.MaxDBAge.Duration == 0 {
		p.MaxDBAge.Duration = e.DBMaxAge
	}
	now := e.now()
	findings, err := e.Store.ListFindings(ctx, store.FindingFilter{Digest: digest})
	if err != nil {
		return gate.Result{}, err
	}
	decisions, err := e.Store.LatestDecisions(ctx)
	if err != nil {
		return gate.Result{}, err
	}
	in := gate.Input{Image: image, Digest: digest, Policy: source, Now: now}
	sla := config.SLA(e.Decisions.SLADays)
	for _, f := range findings {
		var d *store.Decision
		if x, ok := decisions[f.ID]; ok {
			d = &x
		}
		in.Findings = append(in.Findings, report.FindingRow(f, f.State, now, sla, d))
	}
	sc, err := e.Store.LatestScan(ctx, digest)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return gate.Result{}, err
	default:
		in.Evidence = &gate.Evidence{
			ScanID: sc.ID, Status: sc.Status, FinishedAt: sc.FinishedAt, Tools: sc.Tools,
			Fresh: scanID != 0 && sc.ID == scanID,
		}
	}
	return gate.Evaluate(p, in), nil
}
