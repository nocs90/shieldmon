# Adding a report format

Report formats are renderers over the computed `report.Monthly` value; they never query
the store themselves.

```go
// internal/report/render_junit.go
func init() {
	RegisterFormat(Format{
		Name:        "junit",
		Description: "JUnit XML: one failing test case per open finding, for CI dashboards",
		Render:      renderJUnit,
	})
}

func renderJUnit(w io.Writer, r Monthly) error { … }
```

`shieldmon report monthly -o junit` and `shieldmon plugins` pick it up automatically. Built in:
`md`, `json`, `csv`, `html`, `remediation-plan`, `remediation-plan-excel`, `sarif`
(`render_sarif.go` is a complete example with schema validation in its test).

Requirements:

- Escape hostile strings for the target syntax (package names and titles come from image
  content): see `csvSafe` and `mdEscape`.
- Deterministic output (sorted, no map iteration order) so golden-file tests are stable.
- A golden-file test and, for structured formats, validation against the official schema.
