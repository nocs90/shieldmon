package cli

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/nocs90/shieldmon/internal/config"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
	"github.com/nocs90/shieldmon/internal/runtimectx"
	"github.com/nocs90/shieldmon/internal/sbom"
	"github.com/nocs90/shieldmon/internal/store"
)

// runtimeSet loads the configured cluster exports (docs/adr/0029-runtime-context.md). One
// that cannot be read, is malformed or is stale is left out with a warning to warn, and
// returned among the failures for reports to state: runtime context only orders findings,
// it never changes their state.
func (a *app) runtimeSet(warn io.Writer) (runtimectx.Set, []runtimectx.Failure) {
	var set runtimectx.Set
	var failed []runtimectx.Failure
	now := time.Now()
	for _, inv := range a.cfg.Runtime.Inventories {
		loaded, err := runtimectx.Load(inv.Path, inv.Cluster, a.cfg.Runtime.MaxAge.Duration, now)
		if err != nil {
			reason := redact.Error(err)
			fmt.Fprintf(warn, "warning: runtime context of cluster %s left out: %s\n", inv.Cluster, reason)
			failed = append(failed, runtimectx.Failure{Cluster: inv.Cluster, Reason: reason})
			continue
		}
		set = append(set, loaded)
	}
	return set, failed
}

// monthlyReport is the monthly report of the month containing ref, as of now, with base
// lineage, owners and runtime context: the same for 'report monthly' and the server.
func (a *app) monthlyReport(ctx context.Context, warn io.Writer, ref, now time.Time) (report.Monthly, error) {
	sla, err := config.SLAProfile(a.cfg.SLA.Profile, a.cfg.SLA.Days)
	if err != nil {
		return report.Monthly{}, err
	}
	r, err := report.BuildMonthly(ctx, a.store, report.MonthPeriod(ref), a.cfg.SLA.Profile, sla, now)
	if err != nil {
		return report.Monthly{}, err
	}
	read := func(b store.SBOM) ([]byte, error) { return a.engine.ReadSBOM(b, sbom.MaxBytes) }
	if err := report.AddBaseLineage(ctx, a.store, &r, a.engine.Bases, read); err != nil {
		return report.Monthly{}, err
	}
	report.AddOwners(&r, a.owners)
	set, failed := a.runtimeSet(warn)
	if err := report.AddRuntime(ctx, a.store, &r, set, failed); err != nil {
		return report.Monthly{}, err
	}
	return r, nil
}
