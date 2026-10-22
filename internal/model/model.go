// Package model holds the domain types shared across ShieldMon packages.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Severity is the normalized severity scale used internally.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityNegligible
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityUnknown:    "unknown",
	SeverityNegligible: "negligible",
	SeverityLow:        "low",
	SeverityMedium:     "medium",
	SeverityHigh:       "high",
	SeverityCritical:   "critical",
}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// ParseSeverity maps scanner-specific severity labels onto the internal scale.
func ParseSeverity(v string) Severity {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical":
		return SeverityCritical
	case "high", "important":
		return SeverityHigh
	case "medium", "moderate":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "negligible", "none", "info", "informational":
		return SeverityNegligible
	default:
		return SeverityUnknown
	}
}

// State is a finding lifecycle state. See docs/adr/0004-finding-lifecycle.md.
type State string

const (
	StateOpen          State = "open"
	StateTriaged       State = "triaged"
	StateInRemediation State = "in_remediation"
	StateReopened      State = "reopened"
	StateFixed         State = "fixed"
	StateRiskAccepted  State = "risk_accepted"
	StateNotAffected   State = "not_affected"
	// StateSuperseded marks a finding whose digest was replaced by a successor
	// digest that still carries the same vulnerability; tracking continues on
	// the successor finding, which inherits first-detection time and triage.
	StateSuperseded State = "superseded"
	// StateWithdrawn marks a finding that disappeared from the same immutable
	// digest after a vulnerability DB update (advisory rejected/withdrawn).
	// It is not a fix and is reported separately.
	StateWithdrawn State = "withdrawn"
)

// AllStates lists every valid state, in display order.
var AllStates = []State{
	StateOpen, StateTriaged, StateInRemediation, StateReopened,
	StateRiskAccepted, StateNotAffected, StateFixed, StateSuperseded, StateWithdrawn,
}

// Active reports whether the finding still requires remediation work.
func (s State) Active() bool {
	switch s {
	case StateOpen, StateTriaged, StateInRemediation, StateReopened:
		return true
	}
	return false
}

// Suppressed reports whether the finding is present but covered by a VEX-style decision.
func (s State) Suppressed() bool {
	return s == StateRiskAccepted || s == StateNotAffected
}

// Terminal reports whether the finding is closed for good on its digest.
func (s State) Terminal() bool {
	return s == StateFixed || s == StateSuperseded || s == StateWithdrawn
}

// ParseState validates a state name.
func ParseState(v string) (State, error) {
	for _, s := range AllStates {
		if string(s) == v {
			return s, nil
		}
	}
	return "", fmt.Errorf("unknown state %q", v)
}

// Tool describes a scanner binary and the vulnerability DB it used.
type Tool struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	DBVersion string    `json:"db_version,omitempty"`
	DBBuilt   time.Time `json:"db_built,omitzero"`
}

// DBAge returns how old the vulnerability DB was at time now; zero if unknown.
func (t Tool) DBAge(now time.Time) time.Duration {
	if t.DBBuilt.IsZero() {
		return 0
	}
	return now.Sub(t.DBBuilt)
}

// RawMatch is a single vulnerability match as reported by one scanner,
// before normalization and cross-scanner deduplication.
type RawMatch struct {
	Scanner     string
	VulnID      string
	Aliases     []string
	PURL        string
	PkgName     string
	PkgVersion  string
	PkgType     string
	Severity    Severity
	CVSSScore   float64
	CVSSVector  string
	EPSS        float64
	KEV         bool
	FixVersions []string
	FixState    string
	DataSource  string
	Title       string
}

// FixState is the vendor's remediation status for a vulnerable package.
type FixState string

const (
	FixUnknown  FixState = "unknown"
	FixFixed    FixState = "fixed"     // a fixed version exists
	FixNotFixed FixState = "not_fixed" // affected, no fix released yet
	FixWontFix  FixState = "wont_fix"  // vendor will not fix (or end of life)
)

// ParseFixState maps scanner-specific fix statuses onto FixState.
func ParseFixState(v string) FixState {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_"))) {
	case "fixed":
		return FixFixed
	case "not_fixed", "affected", "fix_deferred", "under_investigation":
		return FixNotFixed
	case "wont_fix", "will_not_fix", "end_of_life":
		return FixWontFix
	}
	return FixUnknown
}

// Fixable reports whether remediation by upgrading is possible today.
func (m Match) Fixable() bool { return len(m.FixVersions) > 0 || m.FixState == FixFixed }

// Match is a normalized, deduplicated vulnerability match on one digest.
// Its identity is (PURL, VulnID) within the scanned digest.
type Match struct {
	VulnID      string   `json:"vuln_id"`
	Aliases     []string `json:"aliases,omitempty"`
	PURL        string   `json:"purl"`
	PkgKey      string   `json:"pkg_key"` // PURL without version: lineage across digests
	PkgName     string   `json:"pkg_name"`
	PkgVersion  string   `json:"pkg_version"`
	PkgType     string   `json:"pkg_type"`
	Severity    Severity `json:"-"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	EPSS        float64  `json:"epss,omitempty"`
	KEV         bool     `json:"kev,omitempty"`
	FixVersions []string `json:"fix_versions,omitempty"`
	FixState    FixState `json:"fix_state"`
	Scanners    []string `json:"scanners"`
	Title       string   `json:"title,omitempty"`
}

// Key is the per-digest identity of a match.
func (m Match) Key() string { return m.PURL + "|" + m.VulnID }

// LineageKey identifies "the same problem" across successive digests of a
// target, independent of the package version.
func (m Match) LineageKey() string { return m.PkgKey + "|" + m.VulnID }

// Platform is an OS/architecture pair, e.g. linux/amd64.
type Platform struct {
	OS           string
	Architecture string
	Variant      string
}

func (p Platform) String() string {
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

// ParsePlatform parses "os/arch[/variant]".
func ParsePlatform(v string) (Platform, error) {
	parts := strings.Split(v, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return Platform{}, fmt.Errorf("invalid platform %q (want os/arch[/variant])", v)
	}
	p := Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}
