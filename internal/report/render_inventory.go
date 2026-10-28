package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() {
	RegisterInventoryFormat(InventoryFormat{Name: "json", Description: "full inventory as JSON", Render: func(w io.Writer, inv Inventory) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	}})
	RegisterInventoryFormat(InventoryFormat{Name: "csv", Description: "one row per monitored image", Render: renderInventoryCSV})
	RegisterInventoryFormat(InventoryFormat{Name: "md", Description: "human-readable Markdown inventory", Render: renderInventoryMarkdown})
}

var inventoryHeader = []string{
	"ref", "platform", "digest", "repository", "monitored_since", "last_resolved", "digest_changes",
	"last_scan", "last_scan_kind", "last_scan_status", "last_complete_scan", "scanners", "sboms",
	"open_critical", "open_high", "open_medium", "open_low", "open_other", "gaps", "retired_at",
}

// openSeverities are the columns of open findings; the rest is "other".
var openSeverities = []string{"critical", "high", "medium", "low"}

func renderInventoryCSV(w io.Writer, inv Inventory) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(inventoryHeader); err != nil {
		return err
	}
	for _, img := range inv.Images {
		var scanAt, kind, status string
		if s := img.LastScan; s != nil {
			scanAt, kind, status = timeOrEmpty(s.At), s.Kind, s.Status
		}
		rec := []string{
			img.Ref, img.Platform, img.Digest, img.Repository, timeOrEmpty(img.MonitoredSince), timeOrEmpty(img.LastResolved),
			strconv.Itoa(img.DigestChanges), scanAt, kind, status, timeOrEmpty(img.LastComplete), scanners(img), sbomList(img),
		}
		for _, sev := range openSeverities {
			rec = append(rec, strconv.Itoa(img.Open[sev]))
		}
		rec = append(rec, strconv.Itoa(otherOpen(img.Open)), strings.Join(img.Gaps, "; "), timeOrEmpty(img.RetiredAt))
		for i, v := range rec {
			rec[i] = CSVSafe(oneLine(v))
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func renderInventoryMarkdown(w io.Writer, inv Inventory) error {
	b := &strings.Builder{}
	s := inv.Summary
	fmt.Fprintf(b, "# Monitored image inventory\n\nGenerated: %s · Monitored targets: %d · Distinct digests: %d · With evidence gaps: %d · Retired: %d\n\n",
		inv.GeneratedAt.Format(time.RFC3339), s.Targets, s.Digests, s.WithGaps, s.Retired)
	if len(s.Gaps) > 0 {
		b.WriteString("## Evidence gaps\n\n| Gap | Images |\n|---|---:|\n")
		gaps := make([]string, 0, len(s.Gaps))
		for g := range s.Gaps {
			gaps = append(gaps, g)
		}
		slices.Sort(gaps)
		for _, g := range gaps {
			fmt.Fprintf(b, "| %s | %d |\n", mdEscape(g), s.Gaps[g])
		}
		b.WriteString("\n")
	}
	b.WriteString("## Images\n\n| Image | Digest | Last complete scan | Scanners | SBOMs | Open (C/H/M/L) | Gaps |\n|---|---|---|---|---|---|---|\n")
	for _, img := range inv.Images {
		digest := "—"
		if img.Digest != "" {
			digest = "`" + mdEscape(img.Digest) + "`"
			if len(img.Digest) > 19 {
				digest = "`" + mdEscape(img.Digest[:19]) + "…`"
			}
		}
		gaps := mdEscape(strings.Join(img.Gaps, ", "))
		if !img.RetiredAt.IsZero() {
			gaps = "retired " + img.RetiredAt.UTC().Format(time.DateOnly)
		}
		fmt.Fprintf(b, "| %s (%s) | %s | %s | %s | %s | %d/%d/%d/%d | %s |\n",
			mdEscape(img.Ref), mdEscape(img.Platform), digest, timeOrEmpty(img.LastComplete), mdEscape(scanners(img)),
			mdEscape(sbomGenerators(img)), img.Open["critical"], img.Open["high"], img.Open["medium"], img.Open["low"], gaps)
	}
	if inv.Changes != nil {
		b.WriteString("\n")
		writeChangesMarkdown(b, *inv.Changes)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// scanners lists the tools of the last scan with their DB build dates.
func scanners(img Image) string {
	if img.LastScan == nil {
		return ""
	}
	var out []string
	for _, t := range img.LastScan.Tools {
		s := t.Name + " " + t.Version
		if !t.DBBuilt.IsZero() {
			s += " (DB " + t.DBBuilt.UTC().Format(time.DateOnly) + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, "; ")
}

func sbomList(img Image) string {
	var out []string
	for _, b := range img.SBOMs {
		out = append(out, fmt.Sprintf("%s %s %s sha256:%s", b.Generator, b.Version, b.Format, b.SHA256))
	}
	return strings.Join(out, "; ")
}

func sbomGenerators(img Image) string {
	var out []string
	for _, b := range img.SBOMs {
		if !slices.Contains(out, b.Generator) {
			out = append(out, b.Generator)
		}
	}
	return strings.Join(out, ", ")
}

func otherOpen(open map[string]int) int {
	n := 0
	for sev, c := range open {
		if !slices.Contains(openSeverities, sev) {
			n += c
		}
	}
	return n
}
