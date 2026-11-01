package charts_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/charts/chartstest"
	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/scanner"
)

// fakeHelmEnv makes the test binary act as helm: it checks the arguments as Render passes
// them and prints a Deployment per values file, with the image the file names.
const fakeHelmEnv = "SHIELDMON_FAKE_HELM"

func init() {
	mode := os.Getenv(fakeHelmEnv)
	if mode == "" {
		return
	}
	if err := fakeHelm(mode, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "fake helm:", err)
		os.Exit(2)
	}
	os.Exit(0)
}

func fakeHelm(mode string, args []string) error {
	sep := slices.Index(args, "--")
	if len(args) < 4 || args[0] != "template" || sep < 0 || len(args) != sep+3 {
		return fmt.Errorf("unexpected arguments %q", args)
	}
	for _, a := range args[1:sep] {
		if !strings.HasPrefix(a, "--") || !strings.Contains(a, "=") && a != "--skip-schema-validation" {
			return fmt.Errorf("flag %q is not --name=value", a)
		}
		name, _, _ := strings.Cut(a, "=")
		if slices.Contains([]string{"--enable-dns", "--post-renderer", "--dependency-update", "--validate"}, name) {
			return fmt.Errorf("flag %s must never reach helm", a)
		}
	}
	if home := os.Getenv("HOME"); home == "" || home != os.Getenv("TMPDIR") {
		return fmt.Errorf("HOME %q is not the scratch directory %q", home, os.Getenv("TMPDIR"))
	}
	release, chart := args[sep+1], args[sep+2]
	if _, err := os.Stat(chart); err != nil {
		return err
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "XDG_CACHE_HOME=") && kv != "XDG_CACHE_HOME=" {
			return fmt.Errorf("helm sees %s", kv)
		}
	}
	switch mode {
	case "fail":
		return errors.New("Error: template: boom")
	case "empty":
		return nil
	case "flood":
		line := strings.Repeat("# filler\n", 1<<16)
		for range manifests.MaxBytes/len(line) + 2 {
			fmt.Print(line)
		}
		return nil
	case "slow":
		time.Sleep(time.Minute)
	}
	fmt.Printf("apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: %s}\nspec:\n  template:\n    spec:\n      containers: [{name: web, image: \"nginx:1.27\"}]\n", release)
	for i, a := range args[1:sep] {
		if v, ok := strings.CutPrefix(a, "--values="); ok {
			data, err := os.ReadFile(v)
			if err != nil {
				return err
			}
			img := strings.TrimSpace(strings.TrimPrefix(string(data), "image:"))
			fmt.Printf("---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: v%d}\nspec:\n  template:\n    spec:\n      containers: [{name: c, image: %q}]\n", i, img)
		}
	}
	return nil
}

func renderer(t *testing.T, mode string) (charts.Renderer, string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, none, err := scanner.SelectSandbox("none")
	if err != nil {
		t.Fatal(err)
	}
	data := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(data, "user-cache"))
	stage := filepath.Join(data, "stage")
	return charts.Renderer{
		Helm: self,
		Runner: scanner.Runner{
			Timeout: 20 * time.Second, Sandbox: none, TempDir: filepath.Join(data, "tmp"),
			CacheDir: filepath.Join(data, "cache"), ExtraEnv: []string{fakeHelmEnv + "=" + mode},
		},
		StageDir: stage,
	}, stage
}

func profile() charts.Profile {
	return charts.Profile{Name: "default", Release: "web", Namespace: "shop"}
}

func TestRenderImages(t *testing.T) {
	r, stage := renderer(t, "ok")
	p := profile()
	p.Values = [][]byte{[]byte("image: ghcr.io/org/a:1\n"), []byte("image: ghcr.io/org/b:2\n")}
	p.KubeVersion, p.APIVersions, p.SkipSchemaValidation = "1.33", []string{"monitoring.coreos.com/v1"}, true
	res, err := r.Render(context.Background(), chartstest.Archive(t, "web", "1.2.3"), "web", "1.2.3", p)
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, img := range res.Images {
		refs = append(refs, img.Ref)
	}
	if want := []string{"ghcr.io/org/a:1", "ghcr.io/org/b:2", "nginx:1.27"}; !slices.Equal(refs, want) {
		t.Fatalf("images %v, want %v", refs, want)
	}
	if entries, err := os.ReadDir(stage); err != nil || len(entries) != 0 {
		t.Errorf("staging directory left behind: %v %v", entries, err)
	}

	// A render killed before cleaning up leaves its values behind: the next one removes them.
	stale, fresh := filepath.Join(stage, "chart-stale"), filepath.Join(stage, "chart-fresh")
	for _, d := range []string{stale, fresh} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Render(context.Background(), chartstest.Archive(t, "web", "1.2.3"), "web", "1.2.3", profile()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale staging directory kept: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a recent staging directory (another render) was removed: %v", err)
	}
}

func TestRenderRefusesWhatItShouldNotRun(t *testing.T) {
	ok := chartstest.Archive(t, "web", "1.2.3")
	r, _ := renderer(t, "ok")
	for name, tc := range map[string]struct {
		r              charts.Renderer
		archive        []byte
		chart, version string
		p              func(*charts.Profile)
		want           string
	}{
		"other chart":        {r: r, archive: ok, chart: "api", version: "1.2.3", want: "not a valid chart archive"},
		"other version":      {r: r, archive: ok, chart: "web", version: "1.2.4", want: "not a valid chart archive"},
		"not an archive":     {r: r, archive: []byte("{{ .Values }}"), chart: "web", version: "1.2.3", want: "not a valid chart archive"},
		"flag as release":    {r: r, p: func(p *charts.Profile) { p.Release = "--post-renderer=x" }, want: "release"},
		"long release":       {r: r, p: func(p *charts.Profile) { p.Release = strings.Repeat("a", 54) }, want: "release"},
		"bad namespace":      {r: r, p: func(p *charts.Profile) { p.Namespace = "Shop" }, want: "namespace"},
		"bad kube version":   {r: r, p: func(p *charts.Profile) { p.KubeVersion = "1.33 --debug" }, want: "kube_version"},
		"bad api version":    {r: r, p: func(p *charts.Profile) { p.APIVersions = []string{"-x"} }, want: "api_versions"},
		"huge values":        {r: r, p: func(p *charts.Profile) { p.Values = [][]byte{make([]byte, charts.MaxValuesBytes+1)} }, want: "values"},
		"no sandbox":         {r: charts.Renderer{Helm: r.Helm, StageDir: r.StageDir, Runner: scanner.Runner{TempDir: r.Runner.TempDir}}, want: "sandbox"},
		"no scratch":         {r: charts.Renderer{Helm: r.Helm, StageDir: r.StageDir, Runner: scanner.Runner{Sandbox: r.Runner.Sandbox}}, want: "scratch"},
		"no staging":         {r: charts.Renderer{Helm: r.Helm, Runner: r.Runner}, want: "staging"},
		"comma in staging":   {r: charts.Renderer{Helm: r.Helm, Runner: r.Runner, StageDir: r.StageDir + ",x"}, want: "comma"},
		"no helm configured": {r: charts.Renderer{StageDir: r.StageDir, Runner: r.Runner}, want: "helm"},
	} {
		t.Run(name, func(t *testing.T) {
			p := profile()
			if tc.p != nil {
				tc.p(&p)
			}
			archive, chart, version := tc.archive, tc.chart, tc.version
			if archive == nil {
				archive, chart, version = ok, "web", "1.2.3"
			}
			_, err := tc.r.Render(context.Background(), archive, chart, version, p)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error about %s", err, tc.want)
			}
		})
	}
}

func TestRenderFailures(t *testing.T) {
	archive := chartstest.Archive(t, "web", "1.2.3")
	for mode, want := range map[string]error{
		"empty": manifests.ErrNoObjects,
		"flood": scanner.ErrOutputTooLarge,
	} {
		r, _ := renderer(t, mode)
		if _, err := r.Render(context.Background(), archive, "web", "1.2.3", profile()); !errors.Is(err, want) {
			t.Errorf("%s: got %v, want %v", mode, err, want)
		}
	}
	r, _ := renderer(t, "fail")
	if _, err := r.Render(context.Background(), archive, "web", "1.2.3", profile()); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("failing helm: got %v", err)
	}
	r, _ = renderer(t, "slow")
	r.Runner.Timeout = 200 * time.Millisecond
	if _, err := r.Render(context.Background(), archive, "web", "1.2.3", profile()); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("slow helm: got %v", err)
	}
}
