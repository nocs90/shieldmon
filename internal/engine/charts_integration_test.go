//go:build integration

package engine_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/charts"
	"github.com/nocs90/shieldmon/internal/charts/chartstest"
	"github.com/nocs90/shieldmon/internal/scanner"
)

// TestRealHelm renders charts with the helm scripts/install-scanners.sh installs, in the
// default sandbox, as 'shieldmon charts images' does (docs/adr/0033-chart-rendering.md): the
// profile's values and namespace reach the templates, and nothing is downloaded. What the
// sandbox denies is proven for every process by scannertest.CheckSandbox.
func TestRealHelm(t *testing.T) {
	bin, err := exec.LookPath("helm")
	if err != nil {
		t.Fatal("helm is not in PATH (scripts/install-scanners.sh installs it)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	data := t.TempDir()
	r := charts.Renderer{
		Helm: bin,
		Runner: scanner.Runner{
			Timeout: 2 * time.Minute, Sandbox: defaultSandbox(t),
			TempDir: filepath.Join(data, "tmp"), ScratchQuota: 1 << 30,
		},
		StageDir: filepath.Join(data, "stage"),
	}
	p := charts.Profile{Name: "prod", Release: "web", Namespace: "shop", Values: [][]byte{[]byte("image: ghcr.io/org/web:2\n")}}

	// Helm sets no namespace on objects; charts do, from the release's.
	ns := chartstest.File{Name: "templates/worker.yaml", Body: `apiVersion: apps/v1
kind: Deployment
metadata: {name: worker, namespace: {{ .Release.Namespace }}}
spec:
  template:
    spec:
      containers: [{name: worker, image: {{ printf "ghcr.io/org/worker:%s" .Chart.AppVersion | quote }}}]
`}
	res, err := r.Render(ctx, chartstest.Archive(t, "web", "1.2.3", ns), "web", "1.2.3", p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"ghcr.io/org/web:2":      "Deployment default/web (container web)",
		"ghcr.io/org/worker:1.0": "Deployment shop/worker (container worker)",
	}
	if len(res.Images) != len(want) {
		t.Fatalf("rendered images: %+v", res.Images)
	}
	for _, img := range res.Images {
		if !slices.Contains(img.Where, want[img.Ref]) {
			t.Errorf("rendered %s at %v, want %s", img.Ref, img.Where, want[img.Ref])
		}
	}

	// A chart whose dependency is not bundled fails: rendering never downloads one.
	dep := chartstest.RawArchive(t, "app",
		chartstest.File{Name: "Chart.yaml", Body: "apiVersion: v2\nname: app\nversion: 1.0.0\ndependencies:\n  - {name: redis, version: 1.0.0, repository: https://charts.example.com}\n"},
		chartstest.File{Name: "templates/cm.yaml", Body: "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\n"})
	if _, err := r.Render(ctx, dep, "app", "1.0.0", p); err == nil || !strings.Contains(err.Error(), "redis") {
		t.Errorf("a missing dependency: got %v", err)
	}
}
