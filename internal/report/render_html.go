package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"
)

//go:embed templates/monthly.html.tmpl
var monthlyHTML string

var severityOrder = []string{"critical", "high", "medium", "low", "negligible", "unknown"}

var htmlTmpl = template.Must(template.New("monthly").Funcs(template.FuncMap{
	"date": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Format("2 Jan 2006")
	},
	"month":      func(t time.Time) string { return t.Format("January 2006") },
	"stamp":      func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"short":      shortDigest,
	"severities": func() []string { return severityOrder },
	"pct": func(n, total int) string {
		if total == 0 {
			return "0"
		}
		return fmt.Sprintf("%.2f", float64(n)*100/float64(total))
	},
	"join": strings.Join,
	"fix": func(r Row) string {
		if len(r.FixVersions) > 0 {
			return strings.Join(r.FixVersions, ", ")
		}
		switch r.FixState {
		case "wont_fix":
			return "won't fix"
		case "not_fixed":
			return "no fix yet"
		}
		return "—"
	},
	"deviation": func(d *DecisionInfo) string {
		if d == nil {
			return ""
		}
		switch d.Deviation {
		case "vendor_dependency":
			return "Vendor dependency"
		case "operational_requirement":
			return "Operational requirement"
		}
		if d.State == "not_affected" {
			return "Not affected (VEX)"
		}
		return "Risk accepted"
	},
	"target": func(r Row) string {
		if len(r.Targets) > 0 {
			return strings.Join(r.Targets, ", ")
		}
		return shortDigest(r.Digest)
	},
	"limit": func(rows []Row, n int) []Row {
		if len(rows) > n {
			return rows[:n]
		}
		return rows
	},
	"more": func(rows []Row, n int) int { return max(len(rows)-n, 0) },
	"aging": func() []string {
		out := make([]string, len(AgingBuckets))
		for i, b := range AgingBuckets {
			out[i] = b.Label
		}
		return out
	},
	"maxAging": func(m map[string]int) int {
		mx := 1
		for _, v := range m {
			mx = max(mx, v)
		}
		return mx
	},
	"burndown": burndownSVG,
}).Parse(monthlyHTML))

func init() {
	RegisterFormat(Format{Name: "html", Description: "self-contained HTML summary for stakeholders and auditors", Render: renderHTML})
}

func renderHTML(w io.Writer, r Monthly) error {
	return htmlTmpl.Execute(w, r)
}

// burndownSVG draws the daily open-finding series as an inline SVG. Only
// numbers reach the markup, so it is safe to mark as trusted HTML.
func burndownSVG(days []DayCount) template.HTML {
	if len(days) == 0 {
		return ""
	}
	const w, h, pad = 720.0, 180.0, 28.0
	mx := 1
	for _, d := range days {
		mx = max(mx, d.Open)
	}
	step := 0.0
	if len(days) > 1 {
		step = (w - 2*pad) / float64(len(days)-1)
	}
	x := func(i int) float64 { return pad + float64(i)*step }
	y := func(v int) float64 { return h - pad - float64(v)*(h-2*pad)/float64(mx) }
	var line, area strings.Builder
	fmt.Fprintf(&area, "M%.1f,%.1f ", x(0), h-pad)
	for i, d := range days {
		fmt.Fprintf(&line, "%.1f,%.1f ", x(i), y(d.Open))
		fmt.Fprintf(&area, "L%.1f,%.1f ", x(i), y(d.Open))
	}
	fmt.Fprintf(&area, "L%.1f,%.1f Z", x(len(days)-1), h-pad)
	last := days[len(days)-1]
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" class="chart" role="img" aria-label="Open findings per day">`, w, h)
	fmt.Fprintf(&b, `<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" class="axis"/>`, pad, h-pad, w-pad, h-pad)
	fmt.Fprintf(&b, `<line x1="%.0f" y1="%.0f" x2="%.0f" y2="%.0f" class="grid"/>`, pad, y(mx), w-pad, y(mx))
	fmt.Fprintf(&b, `<text x="%.0f" y="%.1f" class="lbl">%d</text>`, pad-6, y(mx)+4, mx)
	fmt.Fprintf(&b, `<text x="%.0f" y="%.1f" class="lbl">0</text>`, pad-6, h-pad+4)
	fmt.Fprintf(&b, `<path d="%s" class="area"/>`, area.String())
	fmt.Fprintf(&b, `<polyline points="%s" class="line"/>`, strings.TrimSpace(line.String()))
	fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="4" class="dot"/>`, x(len(days)-1), y(last.Open))
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" class="lbl start">%s</text>`, pad, h-6, days[0].Day)
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" class="lbl end">%s</text>`, w-pad, h-6, last.Day)
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // G203: built only from integers and ISO dates above
}
