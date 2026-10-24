package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestHelpWithoutTerminalIsPlain(t *testing.T) {
	out, _, code := run(t, "--help")
	if code != 0 || strings.Contains(out, "\x1b") || strings.ContainsAny(out, "▀▄█") {
		t.Fatalf("help to a non-terminal must have no banner or escapes: %d\n%s", code, out)
	}
	for _, group := range []string{"Monitoring:", "Triage and reporting:", "Setup:"} {
		if !strings.Contains(out, group) {
			t.Errorf("help lacks command group %q", group)
		}
	}
}

func TestPrintableEscapesTerminalControls(t *testing.T) {
	// A package name carrying an OSC 52 clipboard write, a screen clear and a
	// right-to-left override, as hostile image metadata could.
	in := "libssl\x1b]52;c;ZXZpbA==\x07\x1b[2J\u202efake\nFinding #1 [fixed]"
	got := printable(in)
	if strings.ContainsFunc(got, unprintable) {
		t.Fatalf("control characters survived: %q", got)
	}
	want := `libssl\u001b]52;c;ZXZpbA==\u0007\u001b[2J\u202efake\u000aFinding #1 [fixed]`
	if got != want {
		t.Errorf("printable(%q) = %q, want %q", in, got, want)
	}
	if s := "openssl 3.0.13-r0 ✓"; printable(s) != s {
		t.Errorf("printable altered a clean string: %q", printable(s))
	}
}

func TestBanner(t *testing.T) {
	for _, row := range logo {
		if len(row) != len(logo[0]) {
			t.Fatalf("logo rows differ in width: %q", row)
		}
	}
	sgr := regexp.MustCompile("\x1b\\[[0-9;]*m")
	for _, p := range []painter{{}, {color: true}, {color: true, truecolor: true}} {
		var b bytes.Buffer
		writeBanner(&b, p)
		if !p.color && strings.Contains(b.String(), "\x1b") {
			t.Errorf("NO_COLOR banner contains escape sequences")
		}
		for _, line := range strings.Split(b.String(), "\n") {
			if n := utf8.RuneCountInString(sgr.ReplaceAllString(line, "")); n > 80 {
				t.Errorf("%+v: banner line is %d columns wide", p, n)
			}
		}
	}
}
