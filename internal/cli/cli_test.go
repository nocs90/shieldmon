package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Execute(context.Background(), args, &out, &errb)
	return out.String(), errb.String(), code
}

func TestInitAndEmptyQueries(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}

	out, errOut, code := run(t, append([]string{"init"}, common...)...)
	if code != 0 || !strings.Contains(out, "schema v2") {
		t.Fatalf("init: code=%d out=%s err=%s", code, out, errOut)
	}
	// The written template must load cleanly.
	for _, args := range [][]string{
		{"findings", "list"},
		{"targets", "list"},
		{"health"},
		{"report", "monthly", "--month", "2026-10"},
	} {
		out, errOut, code = run(t, append(args, common...)...)
		if code != 0 {
			t.Errorf("%v: code=%d out=%s err=%s", args, code, out, errOut)
		}
	}
}

func TestManualCloseIsRejected(t *testing.T) {
	dir := t.TempDir()
	_, errOut, code := run(t, "--data-dir", dir, "--config", filepath.Join(dir, "missing.yaml"), "findings", "triage", "1")
	if code == 0 {
		t.Fatal("explicit missing config must fail")
	}
	_ = errOut
	_, errOut, code = run(t, "--data-dir", dir, "findings", "accept-risk", "1", "--author", "a", "--justification", "a long enough reason")
	if code == 0 || !strings.Contains(errOut, "not found") {
		t.Fatalf("decision on unknown finding: code=%d err=%s", code, errOut)
	}
}

func TestVersion(t *testing.T) {
	out, _, code := run(t, "version")
	if code != 0 || !strings.HasPrefix(out, "shieldmon ") {
		t.Fatalf("version: %d %q", code, out)
	}
}

func TestMonitorJSONIsValid(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	if _, errOut, code := run(t, append([]string{"init"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	out, errOut, code := run(t, append([]string{"monitor", "-o", "json"}, common...)...)
	if code != 0 {
		t.Fatalf("monitor: %d %s", code, errOut)
	}
	var v struct {
		RunID  int64  `json:"run_id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("monitor -o json is not a single JSON document: %v\n%s", err, out)
	}
	if v.RunID == 0 || v.Status != "ok" {
		t.Fatalf("unexpected monitor JSON: %+v", v)
	}
}
