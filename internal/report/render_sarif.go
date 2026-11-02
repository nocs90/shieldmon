package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

func init() {
	RegisterFormat(Format{
		Name:        "sarif",
		Description: "SARIF 2.1.0: open findings as results, risk acceptances as suppressed results",
		MediaType:   "application/sarif+json",
		Render:      renderSARIF,
	})
}

// SARIF 2.1.0 subset ShieldMon writes. Text fields hold hostile strings: JSON encoding
// escapes them, and only message.text (plain text) is used, never message.markdown.
type (
	sarifLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	sarifRun struct {
		Tool       sarifTool         `json:"tool"`
		Results    []sarifResult     `json:"results"`
		Properties map[string]string `json:"properties"`
	}
	sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	sarifRule struct {
		ID               string         `json:"id"`
		ShortDescription sarifText      `json:"shortDescription"`
		HelpURI          string         `json:"helpUri,omitempty"`
		Properties       map[string]any `json:"properties"`
	}
	sarifText struct {
		Text string `json:"text"`
	}
	sarifResult struct {
		RuleID              string             `json:"ruleId"`
		RuleIndex           int                `json:"ruleIndex"`
		Level               string             `json:"level"`
		Message             sarifText          `json:"message"`
		Locations           []sarifLocation    `json:"locations"`
		PartialFingerprints map[string]string  `json:"partialFingerprints"`
		Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
		Properties          map[string]any     `json:"properties"`
	}
	sarifLocation struct {
		PhysicalLocation sarifPhysical  `json:"physicalLocation"`
		LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
	}
	sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
	}
	sarifArtifact struct {
		URI string `json:"uri"`
	}
	sarifLogical struct {
		Name               string `json:"name"`
		FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
		Kind               string `json:"kind"`
	}
	sarifSuppression struct {
		Kind          string `json:"kind"`
		Status        string `json:"status"`
		Justification string `json:"justification,omitempty"`
	}
)

// SARIFLevel maps severities to SARIF levels.
func SARIFLevel(sev string) string {
	switch sev {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "note"
}

// SARIFResult is one result of a SARIF log: a finding and its level, or a suppressed
// finding with the justification of its decision.
type SARIFResult struct {
	Row           Row
	Level         string
	Suppressed    bool
	Justification string
	// Properties are added to the result's own (finding_id, state, severity…).
	Properties map[string]any
}

func renderSARIF(w io.Writer, r Monthly) error {
	var results []SARIFResult
	for _, x := range r.Open {
		results = append(results, SARIFResult{Row: x, Level: SARIFLevel(x.Severity)})
	}
	// Risk acceptances are suppressed results; not_affected findings are no weakness and no
	// result.
	for _, x := range r.AcceptedRisks {
		if d := x.Decision; d != nil && x.State == "risk_accepted" {
			just := d.Justification
			if d.Deviation != "" {
				just = d.Deviation + ": " + just
			}
			results = append(results, SARIFResult{Row: x, Level: SARIFLevel(x.Severity), Suppressed: true, Justification: just})
		}
	}
	return WriteSARIF(w, results, map[string]string{
		"period_start": r.Period.Start.Format(time.DateOnly), "period_end": r.Period.End.Format(time.DateOnly),
		"generated_at": r.GeneratedAt.Format(time.RFC3339), "sla_profile": r.SLAProfile,
	})
}

// WriteSARIF writes a SARIF 2.1.0 log with one run of ShieldMon: each vulnerability is a
// rule, each result a finding located by its package URL, with fingerprints that stay the
// same across versions and digests of the same images.
func WriteSARIF(w io.Writer, in []SARIFResult, runProps map[string]string) error {
	rules := map[string]*sarifRule{}
	for _, res := range in {
		x := res.Row
		rule, ok := rules[x.VulnID]
		if !ok {
			desc := x.Title
			if desc == "" {
				desc = x.VulnID
			}
			rule = &sarifRule{
				ID: x.VulnID, ShortDescription: sarifText{oneLine(desc)}, HelpURI: "https://osv.dev/vulnerability/" + url.PathEscape(x.VulnID),
				Properties: map[string]any{"tags": []string{"security", "vulnerability"}},
			}
			rules[x.VulnID] = rule
		}
		// GitHub and others rank by security-severity: the highest CVSS seen for the rule.
		if cur, _ := strconv.ParseFloat(stringOr(rule.Properties["security-severity"]), 64); x.CVSS > cur {
			rule.Properties["security-severity"] = strconv.FormatFloat(x.CVSS, 'f', 1, 64)
		}
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	index := map[string]int{}
	driver := sarifDriver{Name: "ShieldMon", InformationURI: "https://github.com/nocs90/shieldmon", Rules: []sarifRule{}}
	for i, id := range ids {
		index[id] = i
		driver.Rules = append(driver.Rules, *rules[id])
	}

	results := []sarifResult{}
	for _, in := range in {
		x := in.Row
		msg := x.Package + " " + x.Version + " is affected by " + x.VulnID
		if len(x.FixVersions) > 0 {
			msg += "; fixed in " + strings.Join(x.FixVersions, ", ")
		}
		res := sarifResult{
			RuleID: x.VulnID, RuleIndex: index[x.VulnID], Level: in.Level, Message: sarifText{oneLine(msg)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{sarifArtifact{purlURI(x.PURL, x.Package)}},
				LogicalLocations: sarifLogicals(x),
			}},
			PartialFingerprints: map[string]string{"shieldmon/v1": sarifFingerprint(x)},
			Properties: map[string]any{
				"finding_id": x.ID, "state": x.State, "severity": x.Severity, "digest": x.Digest,
				"first_detected": dateOrEmpty(x.FirstDetected), "sla_breached": x.SLABreached, "kev": x.KEV,
			},
		}
		if !x.SLADue.IsZero() {
			res.Properties["sla_due"] = dateOrEmpty(x.SLADue)
		}
		if x.EPSS > 0 {
			res.Properties["epss"] = x.EPSS
		}
		if in.Suppressed {
			res.Suppressions = []sarifSuppression{{Kind: "external", Status: "accepted", Justification: oneLine(in.Justification)}}
		}
		for k, v := range in.Properties {
			res.Properties[k] = v
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{driver}, Results: results, Properties: runProps}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func stringOr(v any) string {
	s, _ := v.(string)
	return s
}

// sarifLogicals names the package and the images (targets, or the digest) a result is in.
func sarifLogicals(x Row) []sarifLogical {
	out := []sarifLogical{{Name: x.Package, FullyQualifiedName: x.PURL, Kind: "package"}}
	if len(x.Targets) == 0 {
		return append(out, sarifLogical{Name: x.Digest, Kind: "image"})
	}
	for _, t := range x.Targets {
		out = append(out, sarifLogical{Name: t, FullyQualifiedName: t + "@" + x.Digest, Kind: "image"})
	}
	return out
}

// sarifFingerprint identifies the problem across runs: the vulnerability in a package of the
// same images, whatever the version or digest.
func sarifFingerprint(x Row) string {
	sum := sha256.Sum256([]byte(x.VulnID + "\x00" + x.Package + "\x00" + strings.Join(x.Targets, "\x00")))
	return hex.EncodeToString(sum[:16])
}

// purlURI is the artifact location: the package URL, percent-encoded where it holds
// characters a URI may not (it comes from scanner output). Existing escapes (%40 in npm
// scopes) are kept.
func purlURI(purl, pkg string) string {
	if purl == "" {
		purl = "pkg:generic/" + url.PathEscape(pkg)
	}
	var b strings.Builder
	for i := 0; i < len(purl); i++ {
		c := purl[i]
		escaped := c == '%' && i+2 < len(purl) && isHex(purl[i+1]) && isHex(purl[i+2])
		if escaped || (c > 0x20 && c < 0x7f && !strings.ContainsRune(`"<>\^`+"`{|}%", rune(c))) {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}
