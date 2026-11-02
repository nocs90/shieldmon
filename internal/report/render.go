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
	"unicode"

	"github.com/nocs90/shieldmon/internal/lineage"
)

// Format is a pluggable report renderer. Register new formats (HTML,
// SARIF, remediation plans, ...) from an init function; see docs/extending/report-format.md.
type Format struct {
	Name        string
	Description string
	// MediaType is what the format is served as (`shieldmon serve`); empty is
	// application/octet-stream.
	MediaType string
	// Download marks formats a browser should save rather than show (spreadsheets).
	Download bool
	Render   func(io.Writer, Monthly) error
}

// LookupFormat returns a registered format by name ("markdown" is md).
func LookupFormat(name string) (Format, bool) {
	if name == "markdown" {
		name = "md"
	}
	f, ok := formats[name]
	if ok && f.MediaType == "" {
		f.MediaType = "application/octet-stream"
	}
	return f, ok
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
	RegisterFormat(Format{Name: "json", Description: "full report as JSON", MediaType: "application/json; charset=utf-8", Render: func(w io.Writer, r Monthly) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}})
	RegisterFormat(Format{
		Name: "csv", Description: "flat list of open and risk-accepted findings (see remediation-plan for the worksheet)",
		MediaType: "text/csv; charset=utf-8", Download: true, Render: renderCSV,
	})
	RegisterFormat(Format{Name: "md", Description: "human-readable Markdown report", MediaType: "text/markdown; charset=utf-8", Render: renderMarkdown})
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
			rec[i] = CSVSafe(v)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// CSVSafe neutralizes spreadsheet formula injection in one CSV cell: package
// names and titles come from hostile image content.
func CSVSafe(v string) string {
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

// writeMonthlyBases lists the targets whose base calls for action at the end of the period:
// a rebuild is available, the base is unmaintained, or it could not be verified.
func writeMonthlyBases(b *strings.Builder, r Monthly) {
	if r.Bases == nil {
		return
	}
	s := r.Bases.Status
	fmt.Fprintf(b, "## Base images\n\nOn the newest base: %d · Rebuild available: %d · Base not verified: %d · No known base: %d · Unmaintained base: %d\n\n",
		s[string(lineage.Current)], s[string(lineage.RebuildAvailable)], s[string(lineage.Unknown)], s[string(lineage.None)], r.Bases.Unmaintained)
	if rm := r.Bases.Remedies; len(rm) > 0 {
		fmt.Fprintf(b, "Open findings on images with a known base: a rebuild replaces the package: %d · the newest base has the same version: %d · in the application's layers: %d · unknown: %d\n\n",
			rm[string(lineage.RemedyRebuild)], rm[string(lineage.RemedyBase)], rm[string(lineage.RemedyApplication)], rm[string(lineage.RemedyUnknown)])
	}
	var rows []TargetSummary
	for _, t := range r.TargetSummaries {
		if x := t.Base; x != nil && (x.Status == lineage.RebuildAvailable || x.Status == lineage.Unknown || x.Unmaintained) {
			rows = append(rows, t)
		}
	}
	if len(rows) == 0 {
		b.WriteString("_No image needs a rebuild or a new base._\n\n")
		return
	}
	b.WriteString("| Target | Base | Status | Newest base since | Unmaintained | Successor | Open |\n|---|---|---|---|---|---|---:|\n")
	for _, t := range rows {
		x := t.Base
		unmaintained := ""
		if x.Unmaintained {
			unmaintained = "yes"
		}
		fmt.Fprintf(b, "| %s (%s) | %s | %s | %s | %s | %s | %d |\n", mdEscape(t.Ref), mdEscape(t.Platform), mdEscape(x.BaseRef),
			strings.ReplaceAll(string(x.Status), "_", " "), dateOrEmpty(x.Since), unmaintained, successorCell(*x), t.Open)
	}
	b.WriteString("\n")
}

// mdEscape keeps hostile strings from breaking table layout or injecting markup. A backslash
// is escaped too, or `a\|b` would end the cell.
func mdEscape(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "`", "'", "[", "\\[", "]", "\\]")
	return visible(r.Replace(s))
}

// visible writes control, bidirectional and other invisible format characters as \uXXXX: in
// a terminal they drive it, in a rendered page they reorder or hide text.
func visible(s string) string {
	if !strings.ContainsFunc(s, invisible) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if invisible(r) {
			fmt.Fprintf(&b, "\\u%04x", r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func invisible(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Bidi_Control, unicode.Cf, unicode.Zl, unicode.Zp)
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
		{"Retired with the image (not counted as open, not fixed)", strconv.Itoa(s.RetiredWithAsset)},
	} {
		fmt.Fprintf(b, "| %s | %s |\n", kv[0], kv[1])
	}

	b.WriteString("\n## Open findings by severity\n\n| Severity | Open |\n|---|---:|\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "negligible", "unknown"} {
		if n := r.OpenBySeverity[sev]; n > 0 {
			fmt.Fprintf(b, "| %s | %d |\n", sev, n)
		}
	}
	if len(r.Owners) > 0 {
		b.WriteString("\n## Open findings by owner\n\n| Team | Contact | Targets | Open | Critical | High | Past SLA | KEV |\n|---|---|---:|---:|---:|---:|---:|---:|\n")
		for _, o := range r.Owners {
			team := o.Team
			if team == "-" {
				team = "_unowned_"
			}
			fmt.Fprintf(b, "| %s | %s | %d | %d | %d | %d | %d | %d |\n", team, mdEscape(o.Contact), o.Targets, o.Open,
				o.BySev["critical"], o.BySev["high"], o.Breached, o.KEV)
		}
	}
	renderRuntimeMarkdown(b, r)
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
	b.WriteString("\n")
	writeMonthlyBases(b, r)
	writeChangesMarkdown(b, r.InventoryChanges)
	if d := r.AuditDigest; d.Seq > 0 {
		fmt.Fprintf(b, "---\n\nAudit trail anchor: entry %d, `%s` (save it: `shieldmon audit verify --digest` proves the trail was not rewritten since).\n", d.Seq, d.Hash)
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
