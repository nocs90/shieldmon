package cli

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
