package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/store"
)

// TestRuntimeContextRanksFindings: an image running behind a LoadBalancer ranks its findings
// higher in findings list and in the monthly report; a stale export is left out, said so.
func TestRuntimeContextRanksFindings(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	running, idle := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	db := filepath.Join(dir, "data", "shieldmon.db")
	raw := func(v string) model.RawMatch {
		return model.RawMatch{
			VulnID: v, PURL: "pkg:apk/alpine/zlib@1.2.13-r0", PkgName: "zlib", PkgVersion: "1.2.13-r0",
			Severity: model.SeverityMedium, CVSSScore: 5, Scanner: "grype",
		}
	}
	seedScan(t, db, idle, store.ScanComplete, raw("CVE-2026-0002"))
	seedScan(t, db, running, store.ScanComplete, raw("CVE-2026-0001"))

	inv := filepath.Join(dir, "prod.json")
	export := `{"kind":"List","items":[
 {"kind":"Pod","metadata":{"name":"web","namespace":"shop","labels":{"app":"web"}},
  "status":{"phase":"Running","containerStatuses":[{"imageID":"registry.test/app@` + running + `","state":{"running":{}}}]}},
 {"kind":"Service","metadata":{"name":"web","namespace":"shop"},"spec":{"type":"LoadBalancer","selector":{"app":"web"}}}]}`
	if err := os.WriteFile(inv, []byte(export), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withInventory := func(cluster string) []byte {
		s := strings.Replace(string(b), "  max_age: 48h ", "  max_age: 24h ", 1)
		return []byte(strings.Replace(s, "  inventories: []\n", "  inventories:\n    - { cluster: \""+cluster+"\", path: "+inv+" }\n", 1))
	}
	if err := os.WriteFile(cfg, withInventory("prod"), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := runc("findings", "list", "-o", "json", "--sort", "priority")
	var rows []struct {
		VulnID   string `json:"vuln_id"`
		Priority struct {
			Value   int      `json:"value"`
			Reasons []string `json:"reasons"`
		} `json:"priority"`
		Runtime *struct {
			Pods     int      `json:"pods"`
			Exposure []string `json:"exposure"`
		} `json:"runtime"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 2 {
		t.Fatalf("code=%d err=%s\n%s", code, errOut, out)
	}
	top, other := rows[0], rows[1]
	if top.VulnID != "CVE-2026-0001" || top.Runtime == nil || top.Runtime.Pods != 1 || top.Priority.Value != other.Priority.Value+15 {
		t.Errorf("the running, exposed image ranks first: %+v / %+v", top, other)
	}
	if other.Runtime != nil {
		t.Errorf("an image running nowhere has no runtime context: %+v", other)
	}
	if out, _, _ := runc("report", "monthly"); !strings.Contains(out, "## Runtime context") {
		t.Errorf("monthly report lacks the runtime context:\n%s", out)
	}

	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(inv, old, old); err != nil {
		t.Fatal(err)
	}
	out, errOut, code = runc("findings", "list", "-o", "json")
	if code != 0 || !strings.Contains(errOut, "runtime context of cluster prod left out") || !strings.Contains(errOut, "stale") || strings.Contains(out, `"runtime"`) {
		t.Errorf("a stale export is left out with a warning: code=%d err=%s\n%s", code, errOut, out)
	}

	if err := os.WriteFile(cfg, withInventory("prod cluster"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("findings", "list"); code == 0 || !strings.Contains(errOut, "runtime.inventories[0].cluster") {
		t.Errorf("cluster names are validated: %s", errOut)
	}
}
