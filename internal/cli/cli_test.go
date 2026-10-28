package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/nocs90/shieldmon/internal/oci/ocitest"
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

func TestDoctorReportsScratchFilesystem(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	if _, errOut, code := run(t, append([]string{"init"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	// doctor fails here (no sandbox, maybe no scanners); the scratch line is information.
	out, _, _ := run(t, append([]string{"doctor"}, common...)...)
	if !strings.Contains(out, "• scratch "+filepath.Join(dir, "data", "tmp")+": on the data dir's filesystem") {
		t.Errorf("doctor must say the scratch space shares the data dir's filesystem:\n%s", out)
	}
}

func TestInitSandboxBackend(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}

	out, errOut, code := run(t, append([]string{"init"}, common...)...)
	if code != 0 || !strings.Contains(out, "sandbox: ") {
		t.Fatalf("init must report the sandbox: code=%d out=%s err=%s", code, out, errOut)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "    backend: auto\n") {
		t.Error("scanners are sandboxed by default (backend: auto)")
	}

	out, errOut, code = run(t, append([]string{"init", "--force", "--sandbox", "none"}, common...)...)
	if code != 0 || !strings.Contains(out, "sandbox: none, scanners run unconfined") {
		t.Fatalf("init --sandbox none: code=%d out=%s err=%s", code, out, errOut)
	}
	if b, _ := os.ReadFile(cfg); !strings.Contains(string(b), "    backend: none\n") {
		t.Error("--sandbox must be written to the config")
	}

	if _, errOut, code := run(t, append([]string{"init", "--force", "--sandbox", "chroot"}, common...)...); code == 0 || !strings.Contains(errOut, "unknown backend") {
		t.Errorf("an unknown backend must be refused: code=%d err=%s", code, errOut)
	}
}

func TestTargetsAdd(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	if _, errOut, code := run(t, append([]string{"init", "--sandbox", "none"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	file := filepath.Join(dir, "images.txt")
	if err := os.WriteFile(file, []byte("# production images\n\nalpine:3.20\nghcr.io/org/app:1.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := run(t, append([]string{"targets", "add", "-f", file, "alpine:3.20", "--dry-run"}, common...)...)
	if code != 0 || !strings.Contains(out, "would add 2 target(s)") {
		t.Fatalf("dry run: code=%d out=%s err=%s", code, out, errOut)
	}
	if out, _, _ := run(t, append([]string{"targets", "list"}, common...)...); strings.Contains(out, "alpine") {
		t.Fatal("a dry run must add nothing")
	}
	if out, errOut, code := run(t, append([]string{"targets", "add", "-f", file}, common...)...); code != 0 || !strings.Contains(out, "added 2 target(s)") {
		t.Fatalf("add: code=%d out=%s err=%s", code, out, errOut)
	}
	// The stored form is what monitor registers, so the same image is one target.
	out, _, _ = run(t, append([]string{"targets", "list"}, common...)...)
	if !strings.Contains(out, "index.docker.io/library/alpine:3.20") {
		t.Errorf("targets are stored normalized:\n%s", out)
	}
	if out, _, _ := run(t, append([]string{"targets", "add", "docker.io/library/alpine:3.20"}, common...)...); !strings.Contains(out, "added 0 target(s), 1 already monitored") {
		t.Errorf("the same image under another spelling is already a target:\n%s", out)
	}

	if err := os.WriteFile(file, []byte("alpine:3.20\n-bad ref\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := run(t, append([]string{"targets", "add", "-f", file}, common...)...); code == 0 || !strings.Contains(errOut, "images.txt:2:") {
		t.Errorf("a malformed line must be refused with its line number: code=%d err=%s", code, errOut)
	}
}

func TestTargetsAddRepo(t *testing.T) {
	reg := ocitest.FakeRegistry(t, "robot", "registry-password", 3, 6)
	registry := strings.TrimPrefix(reg.URL, "http://")
	cfgDir := t.TempDir()
	auth := base64.StdEncoding.EncodeToString([]byte("robot:registry-password"))
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"auths":{"`+registry+`":{"auth":"`+auth+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", cfgDir)

	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	if _, errOut, code := run(t, append([]string{"init", "--sandbox", "none"}, common...)...); code != 0 {
		t.Fatal(errOut)
	}
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{registry + "/team/app0", "--latest", "2"}, []string{"team/app0:1.5.0", "team/app0:1.4.0"}},
		{[]string{registry + "/team/app0", "--tag-regex", `^1\.[0-1]\.`}, []string{"team/app0:1.1.0", "team/app0:1.0.0"}},
		{[]string{registry + "/team", "--under", "--latest", "1"}, []string{"team/app0:1.5.0", "team/app1:1.5.0", "team/app2:1.5.0"}},
	} {
		out, errOut, code := run(t, append(append([]string{"targets", "add-repo", "--dry-run"}, c.args...), common...)...)
		if code != 0 {
			t.Fatalf("%v: code=%d err=%s", c.args, code, errOut)
		}
		if n := strings.Count(out, "would add "+registry); n != len(c.want) {
			t.Errorf("%v: %d targets, want %d:\n%s", c.args, n, len(c.want), out)
		}
		for _, w := range c.want {
			if !strings.Contains(out, registry+"/"+w) {
				t.Errorf("%v: missing %s:\n%s", c.args, w, out)
			}
		}
	}
	if _, errOut, code := run(t, append([]string{"targets", "add-repo", registry + "/team/app0", "--tag-regex", "^nothing$"}, common...)...); code == 0 || !strings.Contains(errOut, "no tags") {
		t.Errorf("no matching tag must be an error: code=%d err=%s", code, errOut)
	}
}
