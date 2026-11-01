package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/store"
)

// seedScan records a finished scan of digest with these matches, as a scan would.
func seedScan(t *testing.T, db, digest, status string, raw ...model.RawMatch) {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	if err := st.UpsertArtifact(ctx, store.Artifact{Digest: digest, Repository: "registry.test/app", Platform: "linux/amd64"}, now); err != nil {
		t.Fatal(err)
	}
	id, err := st.CreateScan(ctx, digest, 0, "initial", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ReconcileScan(ctx, store.ReconcileArgs{
		ScanID: id, Digest: digest, Matches: normalize.Merge(raw), Complete: status == store.ScanComplete, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishScan(ctx, id, status, []model.Tool{{Name: "grype", Version: "0.99.0", DBBuilt: now}}, "", now); err != nil {
		t.Fatal(err)
	}
}

func TestGateExitCodes(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	if _, errOut, code := run(t, append([]string{"init", "--sandbox", "none"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	db := filepath.Join(dir, "data", "shieldmon.db")
	bad := "sha256:" + strings.Repeat("a", 64)
	partial := "sha256:" + strings.Repeat("b", 64)
	seedScan(t, db, bad, store.ScanComplete, model.RawMatch{
		VulnID: "CVE-2023-45853", PURL: "pkg:apk/alpine/zlib@1.2.13-r0", PkgName: "zlib", PkgVersion: "1.2.13-r0",
		Severity: model.SeverityCritical, Scanner: "grype",
	})
	seedScan(t, db, partial, store.ScanPartial)
	gate := func(args ...string) (string, string, int) {
		return run(t, append(append([]string{"gate", "--no-scan"}, args...), common...)...)
	}

	out, errOut, code := gate(bad[:13])
	if code != 2 || !strings.Contains(out, "gate FAIL") || !strings.Contains(out, "critical") || errOut != "" {
		t.Errorf("a critical finding fails with status 2 and no error: code=%d out=%s err=%s", code, out, errOut)
	}

	sarif := filepath.Join(dir, "out", "gate.sarif")
	out, _, code = gate("-o", "sarif", "--out", sarif, bad)
	if code != 2 || !strings.Contains(out, "1 fail, 0 warn") {
		t.Errorf("--out keeps a summary on stdout: code=%d out=%s", code, out)
	}
	b, err := os.ReadFile(sarif)
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct{ Properties map[string]string }
	}
	if err := json.Unmarshal(b, &log); err != nil || log.Runs[0].Properties["gate_verdict"] != "fail" {
		t.Errorf("sarif: %v %s", err, b)
	}
	if fi, err := os.Stat(sarif); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("output file mode: %v %v", fi, err)
	}

	if out, _, code := gate(partial); code != 3 || !strings.Contains(out, "gate INDETERMINATE") || !strings.Contains(out, "is partial") {
		t.Errorf("partial evidence: code=%d out=%s", code, out)
	}

	policy := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policy, []byte("rules: [{ name: exploited, action: fail, when: { kev: true } }]\nexit_codes: { fail: 9 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code = gate("--policy", policy, "-o", "json", bad)
	if code != 0 || !strings.Contains(out, `"verdict": "pass"`) || !strings.Contains(out, `"policy": "`+policy+`"`) {
		t.Errorf("the policy file decides: code=%d out=%s", code, out)
	}
	if err := os.WriteFile(policy, []byte("rules: [{ name: any, action: fail, when: {} }]\nexit_codes: { fail: 9 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := gate("--policy", policy, bad); code != 9 {
		t.Errorf("configured fail status: %d", code)
	}

	if err := os.WriteFile(policy, []byte("ignore: [CVE-2023-45853]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := gate("--policy", policy, bad); code != 1 || !strings.Contains(errOut, "field ignore not found") {
		t.Errorf("an invalid policy is an error: code=%d err=%s", code, errOut)
	}
	if _, errOut, code := gate("sha256:" + strings.Repeat("c", 64)); code != 1 || !strings.Contains(errOut, "error:") {
		t.Errorf("an unknown image is an error, not a verdict: code=%d err=%s", code, errOut)
	}
	if _, errOut, code := gate("-o", "html", bad); code != 1 || !strings.Contains(errOut, "want table, json or sarif") {
		t.Errorf("unknown output: code=%d err=%s", code, errOut)
	}
}
