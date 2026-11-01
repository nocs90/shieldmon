package report

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/runtimectx"
	"github.com/nocs90/shieldmon/internal/store"
)

// RuntimeSource is one cluster inventory a report considered (docs/adr/0029-runtime-context.md).
type RuntimeSource struct {
	Cluster string    `json:"cluster"`
	Taken   time.Time `json:"taken,omitzero"`
	Images  int       `json:"images"`
	// Applied is false when the inventory was taken outside the period (it says where
	// images run now, not where they ran then) or could not be used (Reason).
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// ArtifactSource finds the index digest an image was pulled by.
type ArtifactSource interface {
	GetArtifact(ctx context.Context, digest string) (store.Artifact, error)
}

// AddRuntime adds where each open or risk-accepted finding's image runs and reranks those
// rows by priority with it. Only inventories taken within the period, up to when the report
// was generated, apply; the others, and the exports that failed, are listed as not applied.
func AddRuntime(ctx context.Context, src ArtifactSource, r *Monthly, set runtimectx.Set, failed []runtimectx.Failure) error {
	asOf := r.Period.End
	if r.GeneratedAt.Before(asOf) {
		asOf = r.GeneratedAt
	}
	var applied runtimectx.Set
	for _, inv := range set {
		// Periods are half-open: an export taken at the end belongs to the next one.
		ok := !inv.Taken.Before(r.Period.Start) && inv.Taken.Before(r.Period.End) && !inv.Taken.After(r.GeneratedAt)
		s := RuntimeSource{Cluster: inv.Cluster, Taken: inv.Taken, Images: inv.Images(), Applied: ok}
		if !ok {
			s.Reason = "taken outside the period"
		}
		r.Runtime = append(r.Runtime, s)
		if ok {
			applied = append(applied, inv)
		}
	}
	for _, f := range failed {
		r.Runtime = append(r.Runtime, RuntimeSource{Cluster: f.Cluster, Reason: f.Reason})
	}
	if len(applied) == 0 {
		return nil
	}
	lookup := RuntimeLookup(ctx, src, applied)
	for _, rows := range [][]Row{r.Open, r.AcceptedRisks} {
		for i := range rows {
			c, err := lookup(rows[i].Digest)
			if err != nil {
				return err
			}
			if c.Running {
				rows[i].Runtime = &c
				rows[i].prioritize(asOf)
			}
		}
	}
	return nil
}

// RuntimeLookup returns where an image digest runs in set, by its platform manifest digest
// or the index digest it was resolved from (either may be what a kubelet reports).
func RuntimeLookup(ctx context.Context, src ArtifactSource, set runtimectx.Set) func(digest string) (runtimectx.Context, error) {
	digests := runtimeDigests(ctx, src)
	return func(digest string) (runtimectx.Context, error) {
		if len(set) == 0 {
			return runtimectx.Context{}, nil
		}
		ds, err := digests(digest)
		if err != nil {
			return runtimectx.Context{}, err
		}
		return set.Lookup(ds...), nil
	}
}

// RuntimeTotals counts the open findings whose images run, and are exposed, in the
// clusters of the inventories that applied.
type RuntimeTotals struct{ Running, Exposed int }

// RuntimeTotals is computed from the open rows (AddRuntime).
func (r Monthly) RuntimeTotals() RuntimeTotals {
	var t RuntimeTotals
	for _, x := range r.Open {
		if x.Runtime != nil {
			t.Running++
			if x.Runtime.Exposed {
				t.Exposed++
			}
		}
	}
	return t
}

func renderRuntimeMarkdown(b *strings.Builder, r Monthly) {
	if len(r.Runtime) == 0 {
		return
	}
	t := r.RuntimeTotals()
	fmt.Fprintf(b, "\n## Runtime context\n\nOpen findings in images running in the clusters below: %d, reachable from outside a cluster: %d.\n\n", t.Running, t.Exposed)
	b.WriteString("| Cluster | Inventory taken | Images running | Applied |\n|---|---|---:|---|\n")
	for _, s := range r.Runtime {
		applied, taken := "yes", "—"
		if !s.Applied {
			applied = "no (" + mdEscape(truncate(s.Reason, 160)) + ")"
		}
		if !s.Taken.IsZero() {
			taken = s.Taken.Format(time.RFC3339)
		}
		fmt.Fprintf(b, "| %s | %s | %d | %s |\n", mdEscape(s.Cluster), taken, s.Images, applied)
	}
}

// runtimeCell says where a row's image runs: empty when no inventory applied to the report.
// An image no applied export shows is "not seen", not "not running": a cluster without an
// export, or one left out, may run it.
func runtimeCell(x Row, r Monthly) string {
	if !slices.ContainsFunc(r.Runtime, func(s RuntimeSource) bool { return s.Applied }) {
		return ""
	}
	if x.Runtime == nil {
		return "not seen in the applied exports"
	}
	out := fmt.Sprintf("running (%d pods)", x.Runtime.Pods)
	if len(x.Runtime.Exposure) > 0 {
		out += "; exposed: " + strings.Join(x.Runtime.Exposure, "; ")
	}
	return out
}

// runtimeDigests returns a lookup of the digests a kubelet may report for an image: the
// platform manifest digest, and the index digest it was resolved from.
func runtimeDigests(ctx context.Context, src ArtifactSource) func(string) ([]string, error) {
	cache := map[string][]string{}
	return func(digest string) ([]string, error) {
		if ds, ok := cache[digest]; ok {
			return ds, nil
		}
		ds := []string{digest}
		a, err := src.GetArtifact(ctx, digest)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			return nil, err
		case a.IndexDigest != "":
			ds = append(ds, a.IndexDigest)
		}
		cache[digest] = ds
		return ds, nil
	}
}
