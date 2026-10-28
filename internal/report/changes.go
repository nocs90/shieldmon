package report

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/store"
)

// ChangesSource is the subset of the store inventory changes need: append-only history only,
// so that the changes of any past period can be computed again with the same result.
type ChangesSource interface {
	ListTargets(ctx context.Context) ([]store.Target, error)
	DigestHistory(ctx context.Context) ([]store.DigestChange, error)
	TargetEvents(ctx context.Context) ([]store.TargetEvent, error)
	Scans(ctx context.Context, digest string) ([]store.Scan, error)
}

// Changes are what happened to the inventory in a period.
type Changes struct {
	Period   Period         `json:"period"`
	Added    []TargetChange `json:"added"`
	Rebuilt  []Rebuild      `json:"rebuilt"`
	Retired  []TargetChange `json:"retired"`
	Restored []TargetChange `json:"restored"`
}

// TargetChange is a target added, retired or restored.
type TargetChange struct {
	Ref      string    `json:"ref"`
	Platform string    `json:"platform"`
	At       time.Time `json:"at"`
	Actor    string    `json:"actor,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

// Rebuild is a tag that moved to a new digest, with the first scan of the new digest for the
// target: the evidence for the new image.
type Rebuild struct {
	Ref      string    `json:"ref"`
	Platform string    `json:"platform"`
	At       time.Time `json:"at"`
	From     string    `json:"from"`
	To       string    `json:"to"`
	Scan     *ScanInfo `json:"scan,omitempty"`
}

// BuildChanges returns the inventory changes in p, each list oldest first.
func BuildChanges(ctx context.Context, src ChangesSource, p Period) (Changes, error) {
	c := Changes{Period: p, Added: []TargetChange{}, Rebuilt: []Rebuild{}, Retired: []TargetChange{}, Restored: []TargetChange{}}
	in := func(t time.Time) bool { return !t.Before(p.Start) && t.Before(p.End) }
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return c, err
	}
	byID := map[int64]store.Target{}
	for _, t := range targets {
		byID[t.ID] = t
		if in(t.CreatedAt) {
			c.Added = append(c.Added, TargetChange{Ref: t.Ref, Platform: t.Platform, At: t.CreatedAt})
		}
	}
	history, err := src.DigestHistory(ctx)
	if err != nil {
		return c, err
	}
	for _, h := range history {
		if h.Previous == "" || !in(h.ObservedAt) {
			continue
		}
		t := byID[h.TargetID]
		rb := Rebuild{Ref: t.Ref, Platform: t.Platform, At: h.ObservedAt, From: h.Previous, To: h.Digest}
		scans, err := src.Scans(ctx, h.Digest)
		if err != nil {
			return c, err
		}
		for _, s := range scans {
			if s.TargetID == h.TargetID && !s.StartedAt.Before(h.ObservedAt) {
				rb.Scan = &ScanInfo{At: s.StartedAt, Kind: s.Kind, Status: s.Status, Tools: s.Tools}
				break
			}
		}
		c.Rebuilt = append(c.Rebuilt, rb)
	}
	events, err := src.TargetEvents(ctx)
	if err != nil {
		return c, err
	}
	for _, e := range events {
		if !in(e.At) {
			continue
		}
		t := byID[e.TargetID]
		tc := TargetChange{Ref: t.Ref, Platform: t.Platform, At: e.At, Actor: e.Actor, Reason: e.Reason}
		if e.Action == store.ActionRetire {
			c.Retired = append(c.Retired, tc)
		} else {
			c.Restored = append(c.Restored, tc)
		}
	}
	byTime := func(a, b TargetChange) int { return a.At.Compare(b.At) }
	slices.SortStableFunc(c.Added, byTime)
	return c, nil
}

// writeChangesMarkdown writes the changes as a Markdown section (heading level ##).
func writeChangesMarkdown(b *strings.Builder, c Changes) {
	fmt.Fprintf(b, "## Inventory changes (%s to %s)\n\n", c.Period.Start.Format(time.DateOnly), c.Period.End.AddDate(0, 0, -1).Format(time.DateOnly))
	if c.Empty() {
		b.WriteString("No image added, rebuilt, retired or restored.\n\n")
		return
	}
	image := func(ref, platform string) string { return mdEscape(ref) + " (" + mdEscape(platform) + ")" }
	if len(c.Added) > 0 {
		b.WriteString("Added:\n\n")
		for _, a := range c.Added {
			fmt.Fprintf(b, "- %s — %s\n", image(a.Ref, a.Platform), a.At.Format(time.DateOnly))
		}
		b.WriteString("\n")
	}
	if len(c.Rebuilt) > 0 {
		b.WriteString("Rebuilt (new digest):\n\n")
		for _, r := range c.Rebuilt {
			evidence := "not scanned yet"
			if r.Scan != nil {
				evidence = r.Scan.Kind + " scan " + r.Scan.Status + " " + r.Scan.At.Format(time.DateOnly)
			}
			fmt.Fprintf(b, "- %s — %s: `%s` → `%s` (%s)\n", image(r.Ref, r.Platform), r.At.Format(time.DateOnly),
				mdEscape(shortDigestMD(r.From)), mdEscape(shortDigestMD(r.To)), evidence)
		}
		b.WriteString("\n")
	}
	for _, list := range []struct {
		title string
		items []TargetChange
	}{{"Retired", c.Retired}, {"Restored", c.Restored}} {
		if len(list.items) == 0 {
			continue
		}
		b.WriteString(list.title + ":\n\n")
		for _, x := range list.items {
			fmt.Fprintf(b, "- %s — %s by %s: %s\n", image(x.Ref, x.Platform), x.At.Format(time.DateOnly), mdEscape(x.Actor), mdEscape(x.Reason))
		}
		b.WriteString("\n")
	}
}

func shortDigestMD(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

// Empty reports whether nothing changed.
func (c Changes) Empty() bool {
	return len(c.Added)+len(c.Rebuilt)+len(c.Retired)+len(c.Restored) == 0
}
