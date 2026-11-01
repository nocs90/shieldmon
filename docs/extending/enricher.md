# Writing an enricher

An enricher adds facts to matches from data it refreshes on its own
([ADR 0019](../adr/0019-enrichers.md)). Built in: `kev` (`internal/enrich/kev.go`, a complete
example).

```go
type Enricher interface {
	Update(ctx context.Context) error // refresh from the source; keep the data on failure
	UpdatedAt() time.Time             // when the source last confirmed the data
	Enrich(m *model.Match)            // add facts from loaded data, no I/O
}

func init() {
	enrich.Register(enrich.Plugin{
		Name: "epss", Description: "FIRST EPSS scores", Options: []string{"url", "file"},
		Default: false, // opt-in unless it should apply everywhere
		New: func(s enrich.Spec) (enrich.Enricher, error) { … },
	})
}
```

Rules:

- The source is hostile: bound the size and the entry count, validate every field, refuse
  data that is implausible against what is already known, never follow a redirect to plain
  HTTP.
- Keep data in `Spec.CacheDir`, written atomically, owner-only; load it in `New`, so that a
  restart enriches before the first update.
- `Enrich` only adds facts and is idempotent: every scan calls it on every match.
- Options never hold credentials; `Spec.Transport` and `Spec.Now` let tests replace the
  network and the clock.

Prove it with `enrichtest.CheckEnricher` and a fuzz target for the parser.
