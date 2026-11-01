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
// profile's values reach the templates, and the templates cannot reach the network.
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

	res, err := r.Render(ctx, chartstest.Archive(t, "web", "1.2.3"), "web", "1.2.3", p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Images) != 1 || res.Images[0].Ref != "ghcr.io/org/web:2" || !slices.Contains(res.Images[0].Where, "Deployment shop/web (container web)") {
		t.Fatalf("rendered images: %+v", res.Images)
	}

	// A template that resolves a name: confined, it learns nothing (or helm fails), so a
	// chart cannot tell where it is rendered, nor send anything out through DNS.
	probe := chartstest.File{Name: "templates/probe.yaml", Body: `apiVersion: apps/v1
kind: Deployment
metadata: {name: probe}
spec:
  template:
    spec:
      containers: [{name: probe, image: {{ printf "probe.example/%s:1" (getHostByName "kubernetes.io" | default "offline" | replace "." "-" | replace ":" "-") | quote }}}]
`}
	res, err = r.Render(ctx, chartstest.Archive(t, "web", "1.2.4", probe), "web", "1.2.4", p)
	if !scanner.Confined(r.Runner.Sandbox) {
		t.Skip("unconfined here: the network probe proves nothing")
	}
	if err != nil {
		t.Logf("the probe fails to render: %v", err)
		return
	}
	for _, img := range res.Images {
		if strings.HasPrefix(img.Ref, "probe.example/") && img.Ref != "probe.example/offline:1" {
			t.Errorf("a template resolved a name inside the sandbox: %s", img.Ref)
		}
	}
}
