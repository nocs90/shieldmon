package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/runtimectx"
)

// runtimeSet loads the configured cluster exports (docs/adr/0029-runtime-context.md). One
// that cannot be read, is malformed or is stale is left out with a warning, and returned
// among the failures for reports to state: runtime context only orders findings, it never
// changes their state.
func (a *app) runtimeSet(cmd *cobra.Command) (runtimectx.Set, []runtimectx.Failure) {
	var set runtimectx.Set
	var failed []runtimectx.Failure
	now := time.Now()
	for _, inv := range a.cfg.Runtime.Inventories {
		loaded, err := runtimectx.Load(inv.Path, inv.Cluster, a.cfg.Runtime.MaxAge.Duration, now)
		if err != nil {
			reason := redact.Error(err)
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: runtime context of cluster %s left out: %s\n", inv.Cluster, reason)
			failed = append(failed, runtimectx.Failure{Cluster: inv.Cluster, Reason: reason})
			continue
		}
		set = append(set, loaded)
	}
	return set, failed
}
