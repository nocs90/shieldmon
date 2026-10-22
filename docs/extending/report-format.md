# Adding a report format

Report formats are renderers over the computed `report.Monthly` value; they never query
the store themselves.

```go
// internal/report/sarif.go
func init() {
	RegisterFormat(Format{
		Name:        "sarif",
		Description: "SARIF 2.1.0 for code-scanning dashboards",
		Render:      renderSARIF,
	})
}

func renderSARIF(w io.Writer, r Monthly) error { … }
```

`shieldmon report monthly -o sarif` and `shieldmon plugins` pick it up automatically.

Requirements:

- Escape hostile strings for the target syntax (package names and titles come from image
  content): see `csvSafe` and `mdEscape`.
- Deterministic output (sorted, no map iteration order) so golden-file tests are stable.
- A golden-file test and, for structured formats, validation against the official schema.
