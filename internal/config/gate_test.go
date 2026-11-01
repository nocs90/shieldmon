package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePolicy(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadGateOverDefaults(t *testing.T) {
	g, err := LoadGate(writePolicy(t, `
rules:
  - { name: fixable-high, action: fail, when: { severity: high, fixable: true } }
  - { name: anything, action: warn, when: {} }
exempt: []
exit_codes: { warn: 3 }
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Rules) != 2 || g.Rules[0].Name != "fixable-high" || g.Rules[1].When == nil {
		t.Errorf("rules replace the defaults: %+v", g.Rules)
	}
	if g.Exempt == nil || len(g.Exempt) != 0 {
		t.Errorf("exempt: [] means no exemption, got %#v", g.Exempt)
	}
	if g.ExitCodes != (GateExitCodes{Warn: 3, Fail: 2, Indeterminate: 3}) {
		t.Errorf("unset exit codes keep their defaults: %+v", g.ExitCodes)
	}
	if g.MaxEvidenceAge.Duration != 24*time.Hour {
		t.Errorf("max_evidence_age default: %v", g.MaxEvidenceAge)
	}

	// Keys left out keep the defaults: exemptions and rules.
	g, err = LoadGate(writePolicy(t, "max_evidence_age: 2h\n"))
	if err != nil || len(g.Rules) != len(DefaultGate().Rules) || len(g.Exempt) != 2 || g.MaxEvidenceAge.Duration != 2*time.Hour {
		t.Errorf("partial policy = %+v, %v", g, err)
	}
}

func TestGatePolicyRejected(t *testing.T) {
	for _, c := range []struct{ body, want string }{
		{"", "empty policy"},
		{"rules: []\n", "want 1 to 256 rules"},
		{"rules: [{ name: a, action: block, when: {} }]\n", `action "block"`},
		{"rules: [{ name: a, action: fail }]\n", "when is required"},
		{"rules: [{ name: a, action: fail, when: {} }, { name: a, action: warn, when: {} }]\n", "duplicate name"},
		{"rules: [{ name: \"a b\", action: fail, when: {} }]\n", "name"},
		{"rules: [{ name: a, action: fail, when: { severity: urgent } }]\n", `severity "urgent"`},
		{"rules: [{ name: a, action: fail, when: { epss: 50 } }]\n", "probability"},
		{"rules: [{ name: a, action: fail, when: { cvss: .nan } }]\n", "cvss"},
		{"rules: [{ name: a, action: fail, when: { priority: 101 } }]\n", "priority"},
		{"rules: [{ name: a, action: fail, when: { age_days: -1 } }]\n", "age_days"},
		{"rules: [{ name: a, action: fail, when: { vuln: CVE-1 } }]\n", "not found"},
		{"ignore: [CVE-2024-0001]\n", "not found"},
		{"exempt: [fixed]\n", `"fixed"`},
		{"exempt: [risk_accepted, risk_accepted]\n", "twice"},
		{"exit_codes: { fail: 0 }\n", "never exits 0"},
		{"exit_codes: { indeterminate: 0 }\n", "never exits 0"},
		{"exit_codes: { warn: 200 }\n", "0 to 125"},
		{"max_evidence_age: 0s\n", "positive"},
		{"max_db_age: -1h\n", "negative"},
	} {
		_, err := LoadGate(writePolicy(t, c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err = %v, want %q", c.body, err, c.want)
		}
	}
}

func TestGatePolicyBounded(t *testing.T) {
	big := "# " + strings.Repeat("x", MaxGatePolicyBytes) + "\n"
	if _, err := LoadGate(writePolicy(t, big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized policy: %v", err)
	}
}

func TestConcurrencyAndRateLimitValidated(t *testing.T) {
	for _, c := range []struct {
		concurrency int
		rps         float64
		ok          bool
	}{{1, 10, true}, {8, 0, true}, {0, 10, false}, {65, 10, false}, {1, -1, false}} {
		cfg := Default()
		cfg.Scanners.Concurrency, cfg.Limits.RegistryRPS = c.concurrency, c.rps
		if err := cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("concurrency %d, rps %v: %v", c.concurrency, c.rps, err)
		}
	}
}

func TestConfigGateValidated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("gate:\n  exit_codes: { fail: 0 }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, true); err == nil || !strings.Contains(err.Error(), "gate.exit_codes.fail") {
		t.Errorf("config gate section is validated: %v", err)
	}
}
