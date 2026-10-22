package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Format is a pluggable report renderer. Register new formats (HTML,
// SARIF, remediation plans, ...) from an init function; see docs/extending/report-format.md.
type Format struct {
	Name        string
	Description string
	Render      func(io.Writer, Monthly) error
}

var formats = map[string]Format{}

// RegisterFormat makes a report format available. It panics on duplicates.
func RegisterFormat(f Format) {
	if f.Name == "" || f.Render == nil {
		panic("report: RegisterFormat requires Name and Render")
	}
	if _, dup := formats[f.Name]; dup {
		panic("report: duplicate format " + f.Name)
	}
	formats[f.Name] = f
}

// Formats returns the registered formats sorted by name.
func Formats() []Format {
	out := make([]Format, 0, len(formats))
	for _, f := range formats {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func init() {
	RegisterFormat(Format{Name: "json", Description: "full report as JSON", Render: func(w io.Writer, r Monthly) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}})
	RegisterFormat(Format{Name: "csv", Description: "remediation-plan worksheet of open and risk-accepted findings", Render: renderCSV})
	RegisterFormat(Format{Name: "md", Description: "human-readable Markdown report", Render: renderMarkdown})
}

// Render writes the report in the named format.
func Render(w io.Writer, r Monthly, format string) error {
	if format == "markdown" {
		format = "md"
	}
	f, ok := formats[format]
	if !ok {
		var names []string
		for _, f := range Formats() {
			names = append(names, f.Name)
		}
		return fmt.Errorf("unknown format %q (supported: %s)", format, strings.Join(names, ", "))
	}
	return f.Render(w, r)
}

// csvHeader doubles as a remediation-plan worksheet: one row per open or
// risk-accepted finding as of the end of the period.
var csvHeader = []string{
	"finding_id", "state", "severity", "vuln_id", "aliases", "package", "version", "purl",
	"fix_versions", "cvss", "epss", "kev", "targets", "digest", "first_detected", "age_days",
	"sla_due", "sla_breached",
}

func renderCSV(w io.Writer, r Monthly) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	rows := append(append([]Row{}, r.Open...), r.AcceptedRisks...)
	for _, x := range rows {
		rec := []string{
			strconv.FormatInt(x.ID, 10), x.State, x.Severity, x.VulnID, strings.Join(x.Aliases, " "),
			x.Package, x.Version, x.PURL, strings.Join(x.FixVersions, " "),
			strconv.FormatFloat(x.CVSS, 'f', 1, 64), strconv.FormatFloat(x.EPSS, 'f', 5, 64),
			strconv.FormatBool(x.KEV), strings.Join(x.Targets, "; "), x.Digest,
			x.FirstDetected.Format(time.DateOnly), strconv.Itoa(x.AgeDays), dateOrEmpty(x.SLADue),
			strconv.FormatBool(x.SLABreached),
		}
		for i, v := range rec {
			rec[i] = csvSafe(v)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// csvSafe neutralizes spreadsheet formula injection: package names and
// titles come from hostile image content.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		if _, err := strconv.ParseFloat(v, 64); err != nil {
			return "'" + v
		}
	}
	return v
}

func dateOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.DateOnly)
}

// mdEscape keeps hostile strings from breaking table layout or injecting markup.
func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "`", "'", "[", "\\[", "]", "\\]")
	return r.Replace(s)
}

func renderMarkdown(w io.Writer, r Monthly) error {
	b := &strings.Builder{}
	s := r.Summary
	month := r.Period.Start.Format("January 2006")
	fmt.Fprintf(b, "# Container vulnerability ConMon report — %s\n\n", month)
	fmt.Fprintf(b, "Period: %s to %s (UTC) · Generated: %s · SLA profile: `%s` · Targets: %d\n\n",
		r.Period.Start.Format(time.DateOnly), r.Period.End.AddDate(0, 0, -1).Format(time.DateOnly),
		r.GeneratedAt.Format(time.RFC3339), r.SLAProfile, r.Targets)

	b.WriteString("## Summary\n\n| Metric | Value |\n|---|---:|\n")
	for _, kv := range [][2]string{
		{"Open at start of period", strconv.Itoa(s.OpenAtStart)},
		{"Newly opened", strconv.Itoa(s.Opened)},
		{"Reopened (regressions / expired decisions)", strconv.Itoa(s.Reopened)},
		{"Fixed (verified by scan evidence)", strconv.Itoa(s.Fixed)},
		{"Withdrawn (advisory data changed)", strconv.Itoa(s.Withdrawn)},
		{"Risk accepted", strconv.Itoa(s.RiskAccepted)},
		{"Not affected (VEX)", strconv.Itoa(s.NotAffected)},
		{"Open at end of period", strconv.Itoa(s.OpenAtEnd)},
		{"MTTR mean / median (days)", fmt.Sprintf("%.1f / %.1f", s.MTTRMeanDays, s.MTTRMedianDays)},
		{"Open past SLA", strconv.Itoa(s.SLABreaches)},
		{"Open on CISA KEV", strconv.Itoa(s.KEVOpen)},
	} {
		fmt.Fprintf(b, "| %s | %s |\n", kv[0], kv[1])
	}

	b.WriteString("\n## Open findings by severity\n\n| Severity | Open |\n|---|---:|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if n := r.OpenBySeverity[sev]; n > 0 {
			fmt.Fprintf(b, "| %s | %d |\n", sev, n)
		}
	}
	b.WriteString("\n## Aging of open findings\n\n| Age (days) | Open |\n|---|---:|\n")
	for _, bk := range AgingBuckets {
		fmt.Fprintf(b, "| %s | %d |\n", bk.Label, r.Aging[bk.Label])
	}

	if len(r.Burndown) > 0 {
		b.WriteString("\n## Burndown (open findings at end of day)\n\n```\n")
		maxOpen := 1
		for _, d := range r.Burndown {
			maxOpen = max(maxOpen, d.Open)
		}
		for _, d := range r.Burndown {
			fmt.Fprintf(b, "%s %5d %s\n", d.Day, d.Open, strings.Repeat("█", d.Open*40/maxOpen))
		}
		b.WriteString("```\n")
	}

	writeRows := func(title string, rows []Row, limit int, closed bool) {
		fmt.Fprintf(b, "\n## %s (%d)\n\n", title, len(rows))
		if len(rows) == 0 {
			b.WriteString("_None._\n")
			return
		}
		if closed {
			b.WriteString("| # | Severity | Vulnerability | Package | Target | Detected | Fixed | Days |\n|---|---|---|---|---|---|---|---:|\n")
		} else {
			b.WriteString("| # | Severity | Vulnerability | Package | Fix | Target | Age | SLA due |\n|---|---|---|---|---|---|---:|---|\n")
		}
		for i, x := range rows {
			if limit > 0 && i == limit {
				fmt.Fprintf(b, "\n_…and %d more; see the CSV/JSON export._\n", len(rows)-limit)
				break
			}
			target := strings.Join(x.Targets, ", ")
			if target == "" {
				target = shortDigest(x.Digest)
			}
			vuln := x.VulnID
			if x.KEV {
				vuln += " (KEV)"
			}
			if closed {
				fmt.Fprintf(b, "| %d | %s | %s | %s %s | %s | %s | %s | %d |\n", x.ID, x.Severity, mdEscape(vuln),
					mdEscape(x.Package), mdEscape(x.Version), mdEscape(target), x.FirstDetected.Format(time.DateOnly),
					x.ClosedAt.Format(time.DateOnly), int(x.ClosedAt.Sub(x.FirstDetected).Hours()/24))
				continue
			}
			due := dateOrEmpty(x.SLADue)
			if x.SLABreached {
				due += " ⚠"
			}
			fmt.Fprintf(b, "| %d | %s | %s | %s %s | %s | %s | %d | %s |\n", x.ID, x.Severity, mdEscape(vuln),
				mdEscape(x.Package), mdEscape(x.Version), mdEscape(strings.Join(x.FixVersions, ", ")),
				mdEscape(target), x.AgeDays, due)
		}
	}
	writeRows("Open findings", r.Open, 50, false)
	writeRows("Fixed during the period", r.FixedInPeriod, 50, true)
	writeRows("Accepted risks", r.AcceptedRisks, 0, false)

	fmt.Fprintf(b, "\n## Monitoring health (%d open)\n\n", len(r.HealthOpen))
	if len(r.HealthOpen) == 0 {
		b.WriteString("_No open health findings: the monitoring pipeline ran as expected._\n")
	} else {
		b.WriteString("| Check | Subject | Severity | Since | Detail |\n|---|---|---|---|---|\n")
		for _, h := range r.HealthOpen {
			fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n", h.Check, mdEscape(h.Subject), h.Severity,
				h.FirstSeen.Format(time.DateOnly), mdEscape(truncate(h.Detail, 160)))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
