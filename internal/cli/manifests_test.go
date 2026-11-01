package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetsFromManifests(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	chart := `# Source: shop/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata: {name: shop, labels: {helm.sh/chart: shop-1.4.2}}
spec:
  template:
    spec:
      initContainers: [{name: migrate, image: "ghcr.io/acme/shop-migrate:1.4.2"}]
      containers: [{name: web, image: "ghcr.io/acme/shop:1.4.2"}]
---
apiVersion: v1
kind: Pod
metadata: {name: shop-test, annotations: {helm.sh/hook: test}}
spec:
  containers: [{name: t, image: "busybox:1.36"}]
---
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata: {name: shop-db, namespace: shop}
`
	path := filepath.Join(dir, "rendered.yaml")
	if err := os.WriteFile(path, []byte(chart), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runc("targets", "add", "--manifests", path, "--dry-run")
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut)
	}
	for _, ref := range []string{"ghcr.io/acme/shop:1.4.2", "ghcr.io/acme/shop-migrate:1.4.2", "busybox:1.36"} {
		if !strings.Contains(out, ref) {
			t.Errorf("dry run lacks %s:\n%s", ref, out)
		}
	}
	if !strings.Contains(errOut, "Cluster shop/shop-db (postgresql.cnpg.io/v1) is a custom resource") ||
		!strings.Contains(errOut, "busybox:1.36 is used by Helm hooks only") || !strings.Contains(errOut, "3 image(s) in 2 workload(s) of 3 object(s)") {
		t.Errorf("notes and warnings:\n%s", errOut)
	}
	if out, _, _ := runc("targets", "list"); strings.Contains(out, "shop") {
		t.Errorf("a dry run adds nothing:\n%s", out)
	}

	// helm failed and printed nothing: the pipeline must not pass.
	if _, errOut, code := run(t, append([]string{"targets", "add", "--manifests", "-"}, common...)...); code == 0 || !strings.Contains(errOut, "no Kubernetes objects") {
		t.Errorf("stdin without input: code=%d %s", code, errOut)
	}
	hostile := "apiVersion: v1\nkind: Pod\nmetadata: {name: \"x\\e]8;;https://evil\\e\\\\\"}\nspec:\n  containers: [{name: c}]\n"
	if err := os.WriteFile(path, []byte(hostile), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("targets", "add", "--manifests", path); code == 0 || strings.Contains(errOut, "\x1b") || !strings.Contains(errOut, "has no image") {
		t.Errorf("errors escape names from the manifests: %q", errOut)
	}
	bad := chart + "---\napiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec:\n  containers: [{name: c, image: \"Bad Image\"}]\n"
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("targets", "add", "--manifests", path); code == 0 || !strings.Contains(errOut, "not valid references, nothing added") {
		t.Errorf("an invalid image fails the whole read: %s", errOut)
	}
	if out, _, _ := runc("targets", "list"); strings.Contains(out, "shop") {
		t.Errorf("nothing added after an invalid image:\n%s", out)
	}
	if _, errOut, code := runc("targets", "add", "--manifests", "-", "-f", "-"); code == 0 || !strings.Contains(errOut, "stdin") {
		t.Errorf("two readers of stdin: %s", errOut)
	}
}
