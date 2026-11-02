# Adding a chart source

A chart source lists a Helm chart's versions and downloads their archives
([ADR 0032](../adr/0032-chart-sources.md)). It never renders a chart and never sees registry
credentials: registry access goes through `Spec.OCI`, implemented in `internal/oci`.

```go
// internal/charts/gitlab.go
func init() {
	charts.Register(charts.Plugin{
		Name:        "gitlab",
		Description: "Helm charts of a GitLab package registry",
		Options:     []string{"url", "project"},
		New: func(s charts.Spec) (charts.Source, error) { … },
	})
}
```

Rules:

- `Versions` returns valid SemVer versions only, newest first, at most `charts.MaxVersions`.
- `Fetch` writes at most `charts.MaxArchiveBytes` and returns the archive's `sha256:` digest
  (or the manifest digest in a registry). When the source publishes a digest before the
  download, the archive must match it. On error, the caller discards what was written.
- HTTPS only (HTTP to localhost for mirrors), no credentials in URLs; errors name the host and
  status, never a URL that may carry a token.
- Pass `chartstest.CheckPlugin` and `chartstest.CheckSource` over local fixtures
  (`chartstest.Archive` builds valid archives), like the built-in sources' tests.
