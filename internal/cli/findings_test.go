package cli

import (
	"encoding/csv"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/store"
)

// TestFindingsListAndShow drives the triage commands on stored findings: filters, formats and
// the audit trail of one finding.
func TestFindingsListAndShow(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	digest := "sha256:" + strings.Repeat("d", 64)
	seedScan(t, filepath.Join(dir, "data", "shieldmon.db"), digest, store.ScanComplete,
		model.RawMatch{
			VulnID: "CVE-2023-45853", PURL: "pkg:apk/alpine/zlib@1.2.13-r0", PkgName: "zlib", PkgVersion: "1.2.13-r0",
			Severity: model.SeverityCritical, FixVersions: []string{"1.2.13-r1"}, Scanner: "grype",
		},
		model.RawMatch{
			VulnID: "CVE-2024-0001", PURL: "pkg:npm/=evil@1.0.0", PkgName: "=evil", PkgVersion: "1.0.0",
			Severity: model.SeverityLow, Scanner: "grype",
		})

	out, errOut, code := runc("findings", "list", "--state", "open", "--severity", "high")
	if code != 0 || !strings.Contains(out, "CVE-2023-45853") || strings.Contains(out, "CVE-2024-0001") {
		t.Fatalf("list: code=%d err=%s\n%s", code, errOut, out)
	}
	if _, errOut, code := runc("findings", "list", "--state", "closed"); code == 0 || !strings.Contains(errOut, "closed") {
		t.Errorf("unknown state: %s", errOut)
	}

	out, _, code = runc("findings", "list", "-o", "json")
	var list []map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &list) != nil || len(list) != 2 {
		t.Fatalf("json list: %s", out)
	}
	out, _, _ = runc("findings", "list", "-o", "csv")
	recs, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil || len(recs) != 3 {
		t.Fatalf("csv list: %v\n%s", err, out)
	}
	for _, rec := range recs[1:] {
		for _, v := range rec {
			if strings.HasPrefix(v, "=") {
				t.Errorf("unsafe CSV cell %q", v)
			}
		}
	}

	// store.Finding has no JSON tags of its own: "ID" beside the match's "vuln_id".
	id := int(list[0]["ID"].(float64))
	if list[0]["vuln_id"] != "CVE-2023-45853" {
		id = int(list[1]["ID"].(float64))
	}
	out, errOut, code = runc("findings", "show", strconv.Itoa(id))
	if code != 0 || !strings.Contains(out, "CVE-2023-45853") || !strings.Contains(out, "1.2.13-r1") || !strings.Contains(out, "sla due") {
		t.Errorf("show: code=%d err=%s\n%s", code, errOut, out)
	}
	if _, errOut, code := runc("findings", "show", "x1"); code == 0 || !strings.Contains(errOut, "invalid finding ID") {
		t.Errorf("show with a bad ID: %s", errOut)
	}
}
