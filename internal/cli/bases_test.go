package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetBases(t *testing.T) {
	dir := t.TempDir()
	common := []string{"--config", filepath.Join(dir, "config.yaml"), "--data-dir", filepath.Join(dir, "data")}
	runc := func(args ...string) (string, string, int) { return run(t, append(args, common...)...) }
	if _, errOut, code := runc("init", "--sandbox", "none"); code != 0 {
		t.Fatal(errOut)
	}
	if _, errOut, code := runc("targets", "add", "registry.test/app:1", "--base", "registry.test/base@sha256:"+strings.Repeat("a", 64), "--by", "ops"); code == 0 || !strings.Contains(errOut, "name a tag to follow") {
		t.Errorf("a base pinned by digest has nothing to follow: %s", errOut)
	}
	out, errOut, code := runc("targets", "add", "registry.test/app:1", "--base", "ubi9/nodejs-22-minimal", "--by", "ops")
	if code != 0 || !strings.Contains(out, "built on index.docker.io/ubi9/nodejs-22-minimal:latest") {
		t.Fatalf("add with a base, normalized: code=%d out=%s err=%s", code, out, errOut)
	}
	if out, _, _ := runc("targets", "list"); !strings.Contains(out, "index.docker.io/ubi9/nodejs-22-minimal:latest") {
		t.Errorf("targets list shows the base:\n%s", out)
	}
	if _, errOut, code := runc("targets", "set-base", "1", "ubi9/nodejs-22-minimal", "--by", "ops"); code == 0 || !strings.Contains(errOut, "already has that base") {
		t.Errorf("same base again: %s", errOut)
	}
	if _, errOut, code := runc("targets", "set-base", "1", "--by", "ops"); code == 0 || !strings.Contains(errOut, "give a BASE or --none") {
		t.Errorf("neither base nor --none: %s", errOut)
	}
	if out, errOut, code := runc("targets", "set-base", "1", "--none", "--by", "ops"); code != 0 || !strings.Contains(out, "no configured base") {
		t.Errorf("clear: code=%d out=%s err=%s", code, out, errOut)
	}
	if out, errOut, code := runc("report", "inventory"); code != 0 || !strings.Contains(out, "## Base images") {
		t.Errorf("inventory has a base section: code=%d out=%s err=%s", code, out, errOut)
	}
}
