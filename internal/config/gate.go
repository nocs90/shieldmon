package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nocs90/shieldmon/internal/model"
)

// Gate is the policy 'shieldmon gate' decides on (docs/adr/0021-policy-gate.md).
type Gate struct {
	// Rules flag findings; a finding takes the strongest action of the rules it matches.
	Rules []GateRule `yaml:"rules"`
	// Exempt are the decision states that exempt a finding while the decision is in force.
	Exempt []string `yaml:"exempt"`
	// MaxDBAge is how old a matcher's vulnerability DB may be for a pass (0: health.db_max_age).
	MaxDBAge Duration `yaml:"max_db_age,omitempty"`
	// MaxEvidenceAge is how old the latest scan may be with --no-scan.
	MaxEvidenceAge Duration      `yaml:"max_evidence_age"`
	ExitCodes      GateExitCodes `yaml:"exit_codes"`
}

// GateRule flags the findings that meet every condition under When.
type GateRule struct {
	Name   string    `yaml:"name"`
	Action string    `yaml:"action"`
	When   *GateWhen `yaml:"when"`
}

// GateWhen holds a rule's conditions; unset ones are not checked, and none matches every
// finding. Minimums are inclusive.
type GateWhen struct {
	Severity    string   `yaml:"severity,omitempty"`
	CVSS        *float64 `yaml:"cvss,omitempty"`
	EPSS        *float64 `yaml:"epss,omitempty"`
	Priority    *int     `yaml:"priority,omitempty"`
	AgeDays     *int     `yaml:"age_days,omitempty"`
	KEV         *bool    `yaml:"kev,omitempty"`
	Fixable     *bool    `yaml:"fixable,omitempty"`
	SLABreached *bool    `yaml:"sla_breached,omitempty"`
}

// GateExitCodes are the exit statuses of the verdicts other than pass (0); errors exit 1.
type GateExitCodes struct {
	Warn          int `yaml:"warn"`
	Fail          int `yaml:"fail"`
	Indeterminate int `yaml:"indeterminate"`
}

// Gate rule actions.
const (
	GateFail = "fail"
	GateWarn = "warn"
)

// MaxGatePolicyBytes bounds a policy file: it may come from the repository being gated.
const MaxGatePolicyBytes = 1 << 20

const maxGateRules = 256

var gateRuleName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// DefaultGate is the policy without configuration: fail on exploited and critical findings
// and on breached deadlines, warn on high ones.
func DefaultGate() Gate {
	yes := true
	return Gate{
		Rules: []GateRule{
			{Name: "exploited", Action: GateFail, When: &GateWhen{KEV: &yes}},
			{Name: "critical", Action: GateFail, When: &GateWhen{Severity: "critical"}},
			{Name: "past-deadline", Action: GateFail, When: &GateWhen{SLABreached: &yes}},
			{Name: "high", Action: GateWarn, When: &GateWhen{Severity: "high"}},
		},
		Exempt:         []string{string(model.StateNotAffected), string(model.StateRiskAccepted)},
		MaxEvidenceAge: Duration{24 * time.Hour},
		ExitCodes:      GateExitCodes{Warn: 0, Fail: 2, Indeterminate: 3},
	}
}

// LoadGate reads a policy file with the schema of the gate section, over the defaults.
func LoadGate(path string) (Gate, error) {
	g := DefaultGate()
	f, err := os.Open(path)
	if err != nil {
		return g, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxGatePolicyBytes+1))
	if err != nil {
		return g, err
	}
	if len(data) > MaxGatePolicyBytes {
		return g, fmt.Errorf("%s: policy larger than %d bytes", path, MaxGatePolicyBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&g); err != nil {
		if errors.Is(err, io.EOF) {
			return g, fmt.Errorf("%s: empty policy", path)
		}
		return g, fmt.Errorf("%s: %w", path, err)
	}
	if err := g.Validate(); err != nil {
		return g, fmt.Errorf("%s: %w", path, err)
	}
	return g, nil
}

// Validate rejects policies that cannot mean what they say.
func (g Gate) Validate() error {
	if len(g.Rules) == 0 || len(g.Rules) > maxGateRules {
		return fmt.Errorf("gate.rules: want 1 to %d rules", maxGateRules)
	}
	seen := map[string]bool{}
	for i, r := range g.Rules {
		if !gateRuleName.MatchString(r.Name) {
			return fmt.Errorf("gate.rules[%d]: name %q: want letters, digits, '.', '_' or '-' (at most 64)", i, r.Name)
		}
		if seen[r.Name] {
			return fmt.Errorf("gate.rules: duplicate name %q", r.Name)
		}
		seen[r.Name] = true
		if r.Action != GateFail && r.Action != GateWarn {
			return fmt.Errorf("gate.rules.%s: action %q: want fail or warn", r.Name, r.Action)
		}
		if r.When == nil {
			return fmt.Errorf("gate.rules.%s: when is required ('when: {}' matches every finding)", r.Name)
		}
		if err := r.When.validate(); err != nil {
			return fmt.Errorf("gate.rules.%s.when: %w", r.Name, err)
		}
	}
	for i, s := range g.Exempt {
		if s != string(model.StateNotAffected) && s != string(model.StateRiskAccepted) {
			return fmt.Errorf("gate.exempt: %q: want not_affected or risk_accepted", s)
		}
		if slices.Contains(g.Exempt[:i], s) {
			return fmt.Errorf("gate.exempt: %q listed twice", s)
		}
	}
	if g.MaxDBAge.Duration < 0 {
		return fmt.Errorf("gate.max_db_age must not be negative (0: health.db_max_age)")
	}
	if g.MaxEvidenceAge.Duration <= 0 {
		return fmt.Errorf("gate.max_evidence_age must be positive")
	}
	ec := g.ExitCodes
	switch {
	case ec.Warn < 0 || ec.Warn > 125:
		return fmt.Errorf("gate.exit_codes.warn %d: want 0 to 125", ec.Warn)
	case ec.Fail < 1 || ec.Fail > 125:
		return fmt.Errorf("gate.exit_codes.fail %d: want 1 to 125 (a failing gate never exits 0)", ec.Fail)
	case ec.Indeterminate < 1 || ec.Indeterminate > 125:
		return fmt.Errorf("gate.exit_codes.indeterminate %d: want 1 to 125 (an unproven pass never exits 0)", ec.Indeterminate)
	}
	return nil
}

func (w GateWhen) validate() error {
	if w.Severity != "" && model.ParseSeverity(w.Severity) == model.SeverityUnknown {
		return fmt.Errorf("severity %q: want critical, high, medium, low or negligible", w.Severity)
	}
	// Written so that NaN (YAML .nan) is out of range.
	switch {
	case w.CVSS != nil && !(*w.CVSS >= 0 && *w.CVSS <= 10):
		return fmt.Errorf("cvss %v: want 0 to 10", *w.CVSS)
	case w.EPSS != nil && !(*w.EPSS >= 0 && *w.EPSS <= 1):
		return fmt.Errorf("epss %v: want a probability from 0 to 1", *w.EPSS)
	case w.Priority != nil && (*w.Priority < 0 || *w.Priority > 100):
		return fmt.Errorf("priority %d: want 0 to 100", *w.Priority)
	case w.AgeDays != nil && (*w.AgeDays < 0 || *w.AgeDays > MaxPolicyDays):
		return fmt.Errorf("age_days %d: want 0 to %d", *w.AgeDays, MaxPolicyDays)
	}
	return nil
}
