package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
)

// maxDraftFindings bounds the findings an upstream issue draft lists.
const maxDraftFindings = 50

// ChartsMarkdown writes the status of followed charts (docs/adr/0034-chart-tracking.md).
func ChartsMarkdown(w io.Writer, sts []charts.Status, generated time.Time) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "# Followed Helm charts\n\nGenerated: %s\n\n", generated.UTC().Format(time.RFC3339))
	b.WriteString("| Chart | Version | Released | Images (monitored) | With a fix | Neglected |\n|---|---|---|---:|---:|---|\n")
	for _, s := range sts {
		monitored, fixable := 0, 0
		for _, img := range s.Images {
			if img.Monitored {
				monitored++
			}
			fixable += img.Fixable
		}
		version := mdEscape(s.Version)
		if version == "" {
			version = "not rendered yet"
		}
		neglected := ""
		if s.Version != "" {
			neglected = mdEscape(s.Assessment.Verdict())
		}
		fmt.Fprintf(b, "| %s | %s | %s | %d (%d) | %d | %s |\n", mdEscape(s.Chart), version, dateOrEmpty(s.ReleasedAt),
			len(s.Images), monitored, fixable, neglected)
	}
	for _, s := range sts {
		if len(s.Assessment.Overdue) == 0 {
			continue
		}
		fmt.Fprintf(b, "\n## %s %s\n\n| Image | Vulnerability | Package | Fixed in | Detected |\n|---|---|---|---|---|\n", mdEscape(s.Chart), mdEscape(s.Version))
		for _, f := range s.Assessment.Overdue {
			fmt.Fprintf(b, "| %s | %s%s | %s %s | %s | %s |\n", mdEscape(f.Image), mdEscape(f.VulnID), kevMark(f.KEV),
				mdEscape(f.Package), mdEscape(f.Version), mdEscape(strings.Join(f.FixVersions, ", ")), dateOrEmpty(f.FirstDetected))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func kevMark(kev bool) string {
	if kev {
		return " (CISA KEV)"
	}
	return ""
}

// ChartIssueDraft writes a draft issue for the maintainers of a neglected chart: the images
// of its newest release that carry vulnerabilities with a fix, from scan evidence. It is for a
// person to review, check against the project's contribution guidelines and existing issues,
// and submit; ShieldMon never submits it. Every value from scanners or the chart source is
// in a code span, so that it can neither render markup nor mention anyone.
func ChartIssueDraft(w io.Writer, s charts.Status, generated time.Time) error {
	if len(s.Assessment.Overdue) == 0 {
		return fmt.Errorf("chart %s: no finding with a fix past the policy, nothing to report upstream", s.Chart)
	}
	b := &strings.Builder{}
	images := map[string][]charts.Fixable{}
	var order []string
	for i, f := range s.Assessment.Overdue {
		if i == maxDraftFindings {
			break
		}
		if _, ok := images[f.Image]; !ok {
			order = append(order, f.Image)
		}
		images[f.Image] = append(images[f.Image], f)
	}
	fmt.Fprintf(b, "<!-- Draft by ShieldMon, %s. Review it, follow the project's CONTRIBUTING (sign-off, templates), search its issues for duplicates, and submit it yourself. -->\n\n",
		generated.UTC().Format(time.DateOnly))
	fmt.Fprintf(b, "**Title:** Images of %s %s have vulnerabilities with fixes available\n\n", code(s.Chart), code(s.Version))
	where := ""
	if s.Location != "" {
		where = " from " + code(s.Location)
	}
	fmt.Fprintf(b, "The chart %s %s%s ships images with known vulnerabilities that already have fixed versions:\n\n", code(s.Chart), code(s.Version), where)
	for _, img := range order {
		fmt.Fprintf(b, "- %s\n", code(img))
		for _, f := range images[img] {
			kev := ""
			if f.KEV {
				kev = ", on the CISA KEV catalog"
			}
			fmt.Fprintf(b, "  - %s (%s%s) in %s %s, fixed in %s\n", code(f.VulnID), f.Severity, kev, code(f.Package), code(f.Version), code(strings.Join(f.FixVersions, ", ")))
		}
	}
	if n := len(s.Assessment.Overdue); n > maxDraftFindings {
		fmt.Fprintf(b, "- and %d more\n", n-maxDraftFindings)
	}
	b.WriteString("\nUpdating these images (or the base images they are built on) to releases with the fixes would resolve them. ")
	b.WriteString("The findings come from SBOM-based scans of the images the chart renders; please double-check them against your build.\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// code is s as a Markdown code span: no markup, links or mentions inside, on one line, with
// control and bidirectional characters written out (they would drive a terminal, or reorder
// the text of the issue).
func code(s string) string {
	s = strings.NewReplacer("`", "'", "\n", " ", "\r", " ").Replace(s)
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "") + "…"
	}
	s = visible(s)
	if s == "" {
		s = "-"
	}
	return "`" + s + "`"
}
