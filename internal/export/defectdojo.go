package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
)

func init() {
	Register(Plugin{
		Name:        "defectdojo",
		Description: "DefectDojo: each target's open and risk-accepted findings as a Generic Findings Import test, reimported with close_old_findings",
		Options:     []string{"url", "api_key_env", "product_type", "engagement"},
		New:         newDefectDojo,
	})
}

// scanType is DefectDojo's parser for the Generic Findings Import format.
const scanType = "Generic Findings Import"

type defectDojo struct {
	endpoint    *url.URL
	key         string
	productType string
	engagement  string
	client      *http.Client
}

func newDefectDojo(s Spec) (Exporter, error) {
	raw, err := s.Options.String("url", "")
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, errors.New("option url is required: the DefectDojo server")
	}
	u, err := notify.ParseURL("url", raw)
	if err != nil {
		return nil, err
	}
	key, err := s.Secret("api_key_env")
	if err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("option api_key_env is required: the variable holding a DefectDojo API v2 key")
	}
	d := &defectDojo{endpoint: u.JoinPath("api/v2/reimport-scan/"), key: key, client: s.HTTPClient()}
	if d.productType, err = s.Options.String("product_type", "Container images"); err != nil {
		return nil, err
	}
	if d.engagement, err = s.Options.String("engagement", "ShieldMon"); err != nil {
		return nil, err
	}
	return d, nil
}

// genericReport is DefectDojo's Generic Findings Import document; only documented keys are
// used, because unknown keys stop the import.
type genericReport struct {
	Type        string           `json:"type"`
	Version     string           `json:"version,omitempty"`
	Description string           `json:"description"`
	Findings    []genericFinding `json:"findings"`
}

type genericFinding struct {
	Title                  string   `json:"title"`
	Description            string   `json:"description"`
	Severity               string   `json:"severity"`
	Date                   string   `json:"date,omitempty"`
	Mitigation             string   `json:"mitigation,omitempty"`
	References             string   `json:"references,omitempty"`
	CVE                    string   `json:"cve,omitempty"`
	VulnerabilityIDs       []string `json:"vulnerability_ids,omitempty"`
	ComponentName          string   `json:"component_name,omitempty"`
	ComponentVersion       string   `json:"component_version,omitempty"`
	PURL                   string   `json:"purl,omitempty"`
	UniqueIDFromTool       string   `json:"unique_id_from_tool"`
	VulnIDFromTool         string   `json:"vuln_id_from_tool,omitempty"`
	CVSSv3Score            float64  `json:"cvssv3_score,omitempty"`
	EPSSScore              float64  `json:"epss_score,omitempty"`
	KnownExploited         bool     `json:"known_exploited"`
	FixAvailable           bool     `json:"fix_available"`
	FixVersion             string   `json:"fix_version,omitempty"`
	PlannedRemediationDate string   `json:"planned_remediation_date,omitempty"`
	Active                 bool     `json:"active"`
	RiskAccepted           bool     `json:"risk_accepted"`
	Tags                   []string `json:"tags,omitempty"`
}

// Field bounds of DefectDojo's models: longer values fail the import.
const (
	maxTitle       = 500
	maxText        = 4000
	maxComponent   = 500
	maxVersion     = 100
	maxCVE         = 50
	maxToolID      = 500
	maxTags        = 20
	maxDescription = 16 << 10
)

func ddSeverity(s string) string {
	switch s {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	}
	return "Info" // negligible, unknown
}

// genericFindings maps a target's findings: open ones active, risk-accepted ones accepted;
// not_affected is no weakness and is left out. unique_id_from_tool is the problem (the
// vulnerability in the package, any version), with the version only to keep two copies of a
// package apart in one image.
func genericFindings(t Target) []genericFinding {
	keys := map[string]int{}
	type keyed struct {
		row report.Row
		key string
	}
	var rows []keyed
	for _, x := range t.Findings {
		if x.State == "not_affected" {
			continue
		}
		_, pkgKey := normalize.CanonicalPURL(x.PURL, "", x.Package, "")
		k := "shieldmon:" + x.VulnID + ":" + pkgKey
		keys[k]++
		rows = append(rows, keyed{x, k})
	}
	out := make([]genericFinding, 0, len(rows))
	for _, kr := range rows {
		x := kr.row
		key := kr.key
		if keys[key] > 1 {
			key += "@" + x.Version
		}
		f := genericFinding{
			Title:            cut(x.VulnID+" in "+x.Package+" "+x.Version, maxTitle),
			Severity:         ddSeverity(x.Severity),
			Date:             dateOf(x.FirstDetected),
			References:       "https://osv.dev/vulnerability/" + url.PathEscape(x.VulnID),
			VulnerabilityIDs: append([]string{x.VulnID}, x.Aliases...),
			ComponentName:    cut(x.Package, maxComponent),
			ComponentVersion: cut(x.Version, maxVersion),
			PURL:             cut(x.PURL, maxText),
			UniqueIDFromTool: cut(key, maxToolID),
			VulnIDFromTool:   cut(x.VulnID, maxToolID),
			CVSSv3Score:      x.CVSS,
			EPSSScore:        x.EPSS,
			KnownExploited:   x.KEV,
			FixAvailable:     len(x.FixVersions) > 0,
			Active:           true,
			RiskAccepted:     x.State == "risk_accepted",
			Tags:             []string{"shieldmon"},
		}
		if strings.HasPrefix(x.VulnID, "CVE-") {
			f.CVE = cut(x.VulnID, maxCVE)
		}
		if len(x.FixVersions) > 0 {
			f.FixVersion = cut(x.FixVersions[0], maxVersion)
			f.Mitigation = cut("Upgrade "+x.Package+" to "+strings.Join(x.FixVersions, " or ")+" (rebuild the image).", maxText)
		}
		if !x.SLADue.IsZero() {
			f.PlannedRemediationDate = dateOf(x.SLADue)
		}
		if x.Remedy != "" {
			f.Tags = append(f.Tags, "remedy:"+x.Remedy)
		}
		for _, o := range x.Owners {
			if len(f.Tags) < maxTags && o != "-" {
				f.Tags = append(f.Tags, "owner:"+o)
			}
		}
		f.Description = cut(description(t, x), maxDescription)
		out = append(out, f)
	}
	return out
}

func description(t Target, x report.Row) string {
	var b strings.Builder
	if x.Title != "" {
		b.WriteString(x.Title + "\n\n")
	}
	fmt.Fprintf(&b, "Package: %s %s (%s)\nImage: %s (%s), digest %s\nSeverity: %s", x.Package, x.Version, x.PURL, t.Ref, t.Platform, t.Digest, x.Severity)
	if x.CVSS > 0 {
		fmt.Fprintf(&b, ", CVSS %.1f", x.CVSS)
	}
	if x.KEV {
		b.WriteString(", in CISA KEV")
	}
	fmt.Fprintf(&b, "\nState in ShieldMon: %s (finding #%d, first detected %s)", x.State, x.ID, dateOf(x.FirstDetected))
	if d := x.Decision; d != nil && x.State == "risk_accepted" {
		fmt.Fprintf(&b, "\nRisk accepted by %s until %s: %s", d.Author, dateOf(d.ExpiresAt), d.Justification)
	}
	b.WriteString("\nClosure follows scan evidence in ShieldMon; record decisions there.")
	return b.String()
}

func dateOf(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.DateOnly)
}

func (d *defectDojo) report(t Target, b Batch) ([]byte, error) {
	return json.Marshal(genericReport{
		Type: "ShieldMon", Version: b.Tool,
		Description: cut("ShieldMon findings of "+t.Ref+" ("+t.Platform+"), digest "+t.Digest, maxText),
		Findings:    genericFindings(t),
	})
}

func (d *defectDojo) form(t Target, b Batch) (body []byte, contentType string, err error) {
	doc, err := d.report(t, b)
	if err != nil {
		return nil, "", err
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for _, f := range [][2]string{
		{"scan_type", scanType},
		{"product_type_name", d.productType},
		{"product_name", cut(t.Repository, 255)},
		{"engagement_name", d.engagement},
		{"test_title", cut(t.Ref+" ("+t.Platform+")", 255)},
		{"auto_create_context", "true"},
		{"close_old_findings", "true"},
		{"deduplication_on_engagement", "true"},
		{"scan_date", dateOf(b.Now)},
		{"version", t.Digest},
	} {
		if err := w.WriteField(f[0], f[1]); err != nil {
			return nil, "", err
		}
	}
	part, err := w.CreateFormFile("file", "shieldmon.json")
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(doc); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), w.FormDataContentType(), nil
}

func (d *defectDojo) Payloads(b Batch) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, t := range b.Targets {
		doc, err := d.report(t, b)
		if err != nil {
			return nil, err
		}
		out[fileName(t.Ref+"_"+t.Platform)+".defectdojo.json"] = doc
	}
	return out, nil
}

func (d *defectDojo) Export(ctx context.Context, b Batch) (Result, error) {
	res := Result{Failed: map[string]string{}}
	for _, t := range b.Targets {
		body, ct, err := d.form(t, b)
		if err != nil {
			return res, err
		}
		err = notify.Post(ctx, d.client, d.endpoint, ct, body, http.Header{"Authorization": {"Token " + d.key}})
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err != nil {
			res.Failed[t.Ref] = redact.String(fmt.Sprint(err))
			continue
		}
		res.Sent++
	}
	return res, nil
}
