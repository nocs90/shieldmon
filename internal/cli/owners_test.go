package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwners(t *testing.T) {
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
	tmpl := []byte(strings.Replace(string(b), "\nowners: []\n", "\n", 1))
	write := func(extra string) {
		t.Helper()
		if err := os.WriteFile(cfg, append(append([]byte{}, tmpl...), extra...), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("\nowners:\n  - { team: payments, contact: pay-sec@example.com, targets: [\"registry.test/payments/*\"] }\n")
	if _, errOut, code := runc("targets", "add", "registry.test/payments/api:1", "registry.test/tools/cli:1"); code != 0 {
		t.Fatal(errOut)
	}
	out, _, _ := runc("targets", "list")
	if !strings.Contains(out, "OWNER") || !strings.Contains(out, "payments") || strings.Count(out, " -\n") != 1 {
		t.Errorf("targets list shows owners, - for none:\n%s", out)
	}
	if _, errOut, code := runc("findings", "list", "--owner", "billing"); code == 0 || !strings.Contains(errOut, `"billing" is not a team`) {
		t.Errorf("unknown team: %s", errOut)
	}
	if _, errOut, code := runc("findings", "list", "--owner", "-"); code != 0 {
		t.Errorf("unowned filter: %s", errOut)
	}
	if out, errOut, code := runc("report", "monthly", "--month", "2026-10"); code != 0 || !strings.Contains(out, "## Open findings by owner") {
		t.Errorf("monthly by owner: code=%d err=%s\n%s", code, errOut, out)
	}

	write("\nowners:\n  - { team: Payments, targets: [\"registry.test/payments/*\"] }\n")
	if _, errOut, code := runc("targets", "list"); code == 0 || !strings.Contains(errOut, "lowercase") {
		t.Errorf("owners are validated at startup: %s", errOut)
	}
	minimal := "scanners: { sandbox: { backend: none } }\nowners:\n  - { team: payments, targets: [\"registry.test/payments/*\"] }\n" +
		"notifications:\n  channels:\n    - { name: team, notifier: webhook, owners: [billing], options: { url: \"https://hooks.example.com/x\" } }\n"
	if err := os.WriteFile(cfg, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errOut, code := runc("targets", "list"); code == 0 || !strings.Contains(errOut, `"billing" is not a team in owners`) {
		t.Errorf("channel owners must be teams: %s", errOut)
	}
}
