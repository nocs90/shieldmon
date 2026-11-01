package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/charts/chartstest"
)

func TestChartsCommands(t *testing.T) {
	archives := map[string][]byte{
		"1.0.0":       chartstest.Archive(t, "web", "1.0.0"),
		"1.2.0":       chartstest.Archive(t, "web", "1.2.0"),
		"2.0.0-rc.1":  chartstest.Archive(t, "web", "2.0.0-rc.1"),
		"bad":         []byte("not a chart"),
		"mislabelled": chartstest.Archive(t, "api", "9.9.9"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.yaml" {
			_, _ = io.WriteString(w, "entries:\n  web:\n")
			for _, v := range []string{"1.0.0", "1.2.0", "2.0.0-rc.1"} {
				fmt.Fprintf(w, "    - {version: %s, appVersion: \"1.0\", urls: [web-%s.tgz]}\n", v, v)
			}
			_, _ = io.WriteString(w, "  broken:\n    - {version: 1.0.0, urls: [web-bad.tgz]}\n  liar:\n    - {version: 1.0.0, urls: [web-mislabelled.tgz]}\n")
			return
		}
		v := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/web-"), ".tgz")
		if a, ok := archives[v]; ok {
			_, _ = w.Write(a)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entries := "charts:\n"
	for _, c := range []string{"web", "broken", "liar"} {
		entries += fmt.Sprintf("  - { chart: %s, source: http, options: { url: %q } }\n", c, srv.URL)
	}
	conf := strings.Replace(string(b), "charts: []\n", entries, 1)
	if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := runc("charts", "list")
	if code != 0 || !strings.Contains(out, "web") || !strings.Contains(out, srv.URL) {
		t.Fatalf("list: %d %s\n%s", code, errOut, out)
	}
	out, _, code = runc("charts", "versions", "web")
	if code != 0 || strings.Index(out, "2.0.0-rc.1") > strings.Index(out, "1.2.0") || strings.Index(out, "1.2.0") > strings.Index(out, "1.0.0") {
		t.Errorf("versions newest first:\n%s", out)
	}
	file := filepath.Join(dir, "web.tgz")
	out, errOut, code = runc("charts", "fetch", "web", "--out", file)
	if code != 0 || !strings.Contains(out, "web 1.2.0") {
		t.Fatalf("fetch takes the newest release, not a pre-release: %d %s %s", code, out, errOut)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != string(archives["1.2.0"]) {
		t.Errorf("archive written: %v", err)
	}
	if _, errOut, code := runc("charts", "fetch", "broken", "--out", file); code == 0 || !strings.Contains(errOut, charts.ErrArchive.Error()) {
		t.Errorf("a broken archive is refused: %s", errOut)
	}
	if _, errOut, code := runc("charts", "fetch", "liar", "--out", file); code == 0 || !strings.Contains(errOut, `names "api"`) {
		t.Errorf("an archive naming another chart is refused: %s", errOut)
	}
	if _, errOut, code := runc("charts", "versions", "nope"); code == 0 || !strings.Contains(errOut, "no chart") {
		t.Errorf("unknown chart: %s", errOut)
	}

	bad := strings.Replace(string(b), "charts: []\n", "charts:\n  - { chart: web, source: ftp }\n", 1)
	if err := os.WriteFile(cfg, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("charts", "list"); code == 0 || !strings.Contains(errOut, "unknown chart source") {
		t.Errorf("unknown source: %s", errOut)
	}
}

// fakeHelm stands in for helm template: a Deployment for the image each values file names,
// in the namespace given, and one for nginx:1.27.
const fakeHelm = `#!/bin/sh
ns=""
n=0
for a in "$@"; do
  case "$a" in
    --namespace=*) ns="${a#--namespace=}" ;;
    --values=*)
      n=$((n+1))
      img=$(sed -n 's/^image: //p' "${a#--values=}")
      printf -- '---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: v%s, namespace: %s}\nspec:\n  template:\n    spec:\n      containers: [{name: c, image: "%s"}]\n' "$n" "$ns" "$img" ;;
  esac
done
printf -- '---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: base}\nspec:\n  template:\n    spec:\n      containers: [{name: c, image: "nginx:1.27"}]\n'
`

func TestChartsImages(t *testing.T) {
	archive := chartstest.Archive(t, "web", "1.2.0")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.yaml":
			_, _ = io.WriteString(w, "entries:\n  web:\n    - {version: 1.2.0, urls: [web-1.2.0.tgz]}\n")
		case "/web-1.2.0.tgz":
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	helm := filepath.Join(dir, "helm")
	if err := os.WriteFile(helm, []byte(fakeHelm), 0o700); err != nil {
		t.Fatal(err)
	}
	values := filepath.Join(dir, "prod.yaml")
	if err := os.WriteFile(values, []byte("image: ghcr.io/org/prod:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	common := []string{"--config", cfg, "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	write := func(helmBlock string) {
		t.Helper()
		entries := fmt.Sprintf("charts:\n  - chart: web\n    source: http\n    add_targets: true\n    options: { url: %q }\n    profiles:\n"+
			"      - { name: prod, namespace: shop, values_files: [%q] }\n"+
			"      - { name: mirror, values: { image: \"mirror.example.com/org/web:2\" } }\n", srv.URL, values)
		conf := strings.Replace(string(b), "charts: []\n", entries, 1)
		conf = strings.Replace(conf, "helm:\n  path: \"\"\n  sha256: \"\"\n", helmBlock, 1)
		if err := os.WriteFile(cfg, []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(fmt.Sprintf("helm:\n  path: %q\n  sha256: \"\"\n", helm))

	out, errOut, code := runc("charts", "images", "web")
	if code != 0 {
		t.Fatalf("images: %d %s", code, errOut)
	}
	if !strings.Contains(errOut, "unconfined") {
		t.Errorf("rendering without a sandbox is not said: %s", errOut)
	}
	for _, want := range []string{"web 1.2.0", "profiles prod, mirror: 3 image(s)", "ghcr.io/org/prod:1", "mirror.example.com/org/web:2", "Deployment shop/v1"} {
		if !strings.Contains(out, want) {
			t.Errorf("images: no %q in\n%s", want, out)
		}
	}
	if !regexp.MustCompile(`nginx:1\.27\s+prod,mirror`).MatchString(out) {
		t.Errorf("an image of both profiles lists both:\n%s", out)
	}

	out, _, code = runc("charts", "images", "web", "--profile", "mirror", "-o", "json")
	var res struct {
		Version string `json:"version"`
		Images  []struct {
			Ref      string   `json:"ref"`
			Profiles []string `json:"profiles"`
		} `json:"images"`
	}
	if err := json.Unmarshal([]byte(out), &res); code != 0 || err != nil || res.Version != "1.2.0" || len(res.Images) != 2 {
		t.Fatalf("json, one profile: %d %v %+v\n%s", code, err, res, out)
	}
	if _, errOut, code := runc("charts", "images", "web", "--profile", "nope"); code == 0 || !strings.Contains(errOut, `no profile "nope"`) {
		t.Errorf("unknown profile: %s", errOut)
	}

	out, errOut, code = runc("targets", "add", "--chart", "web", "--profile", "prod", "--dry-run")
	if code != 0 || !strings.Contains(out, "ghcr.io/org/prod:1") || !strings.Contains(out, "nginx:1.27") || strings.Contains(out, "mirror.example.com") {
		t.Errorf("targets add --chart: %d %s\n%s", code, errOut, out)
	}
	if _, errOut, code := runc("targets", "add", "--profile", "prod"); code == 0 || !strings.Contains(errOut, "need --chart") {
		t.Errorf("--profile without --chart: %s", errOut)
	}

	// Tracking: nothing recorded, then the newest release with both profiles, its images
	// added as targets; nothing neglected without findings.
	if out, _, code := runc("charts", "history", "web"); code != 0 || !strings.Contains(out, "nothing recorded yet") {
		t.Errorf("history before tracking: %s", out)
	}
	out, errOut, code = runc("charts", "track")
	if code != 0 || !strings.Contains(out, "web: 1.2.0, 3 image(s)") {
		t.Fatalf("track: %d %s\n%s", code, errOut, out)
	}
	if out, _, _ := runc("targets", "list"); !strings.Contains(out, "ghcr.io/org/prod:1") || !strings.Contains(out, "index.docker.io/library/nginx:1.27") {
		t.Errorf("add_targets: the release's images are targets:\n%s", out)
	}
	out, _, code = runc("charts", "status")
	if code != 0 || !regexp.MustCompile(`web\s+1\.2\.0\s+-\s+3\s+0\s+0\s+no`).MatchString(out) {
		t.Errorf("status:\n%s", out)
	}
	if out, _, code := runc("charts", "status", "web", "-o", "md"); code != 0 || !strings.Contains(out, "| web | 1.2.0 |") {
		t.Errorf("status -o md:\n%s", out)
	}
	if out, _, code := runc("charts", "history", "web"); code != 0 || strings.Count(out, "1.2.0  profile") != 2 {
		t.Errorf("history:\n%s", out)
	}
	if _, errOut, code := runc("charts", "draft-issue", "web"); code == 0 || !strings.Contains(errOut, "nothing to report upstream") {
		t.Errorf("draft-issue without overdue findings: %s", errOut)
	}
	if _, errOut, code := runc("charts", "status", "nope"); code == 0 || !strings.Contains(errOut, "no chart") {
		t.Errorf("status of an unknown chart: %s", errOut)
	}

	write(fmt.Sprintf("helm:\n  path: %q\n  sha256: %q\n", helm, strings.Repeat("0", 64)))
	if _, errOut, code := runc("charts", "images", "web"); code == 0 || !strings.Contains(errOut, "checksum mismatch") {
		t.Errorf("a helm that is not the pinned one is refused: %s", errOut)
	}
}
