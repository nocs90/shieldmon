// Package config loads ShieldMon's YAML configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nocs90/shieldmon/internal/lifecycle"
	"github.com/nocs90/shieldmon/internal/model"
)

// Duration is a time.Duration that unmarshals from strings like "72h".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// Tool configures one scanner plugin: where its binary is, its pinned
// SHA-256, and plugin-specific options (validated by the plugin).
type Tool struct {
	Path    string         `yaml:"path,omitempty"`
	SHA256  string         `yaml:"sha256,omitempty"`
	Options map[string]any `yaml:"options,omitempty"`
}

// Registry binds registry hosts to a provider (docs/adr/0013-registry-providers.md). Options
// are validated by the provider and never hold a credential: they name environment variables.
type Registry struct {
	Hosts    []string       `yaml:"hosts"`
	Provider string         `yaml:"provider"`
	Options  map[string]any `yaml:"options,omitempty"`
}

// Channel is one notification channel (docs/adr/0015-notifications.md). Options are validated
// by the notifier and never hold a credential: they name environment variables.
type Channel struct {
	Name     string         `yaml:"name"`
	Notifier string         `yaml:"notifier"`
	Events   []string       `yaml:"events,omitempty"`
	Digest   bool           `yaml:"digest,omitempty"`
	Options  map[string]any `yaml:"options,omitempty"`
}

// Config is the top-level configuration.
type Config struct {
	DataDir  string `yaml:"data_dir"`
	Platform string `yaml:"platform"`

	Scanners struct {
		// Matchers to run on every scan. Each implies its SBOM generator
		// (grype -> syft, trivy -> trivy); see 'shieldmon plugins'.
		Matchers       []string        `yaml:"matchers"`
		Timeout        Duration        `yaml:"timeout"`
		MaxOutputBytes int64           `yaml:"max_output_bytes"`
		Tools          map[string]Tool `yaml:"tools"`
		// Sandbox confines scanner processes (docs/adr/0011-scanner-sandbox.md).
		Sandbox struct {
			Backend string `yaml:"backend"`
		} `yaml:"sandbox"`
	} `yaml:"scanners"`

	Limits struct {
		MaxLayers     int   `yaml:"max_layers"`
		MaxLayerBytes int64 `yaml:"max_layer_bytes"`
		MaxTotalBytes int64 `yaml:"max_total_bytes"`
		// MaxScratchBytes bounds what one scanner process unpacks into its scratch space.
		MaxScratchBytes int64 `yaml:"max_scratch_bytes"`
		// MinFreeDiskBytes stops a scanner before the data dir's disk fills up.
		MinFreeDiskBytes int64 `yaml:"min_free_disk_bytes"`
	} `yaml:"limits"`

	Health struct {
		DBMaxAge        Duration `yaml:"db_max_age"`
		MonitorInterval Duration `yaml:"monitor_interval"`
	} `yaml:"health"`

	SLA struct {
		Profile string         `yaml:"profile"`
		Days    map[string]int `yaml:"days,omitempty"`
	} `yaml:"sla"`

	// Registries come before the built-in providers (docker config, ECR, Google), in order.
	Registries []Registry `yaml:"registries,omitempty"`

	// Decisions bounds risk acceptances (docs/adr/0010-decision-policy.md).
	Decisions struct {
		VendorDependencyMaxDays       int `yaml:"vendor_dependency_max_days"`
		OperationalRequirementMaxDays int `yaml:"operational_requirement_max_days"`
	} `yaml:"decisions"`

	// Notifications are sent after each monitoring cycle (docs/adr/0015-notifications.md).
	Notifications struct {
		DueSoonDays int       `yaml:"due_soon_days"`
		Channels    []Channel `yaml:"channels,omitempty"`
	} `yaml:"notifications"`
}

// TemplateWithSandbox is Template with scanners.sandbox.backend set to backend.
func TemplateWithSandbox(backend string) string {
	return strings.Replace(Template, "    backend: auto\n", "    backend: "+backend+"\n", 1)
}

// Default returns the built-in configuration.
func Default() Config {
	var c Config
	c.DataDir = defaultDataDir()
	c.Platform = "linux/amd64"
	c.Scanners.Matchers = []string{"grype", "trivy"}
	c.Scanners.Timeout = Duration{30 * time.Minute}
	c.Scanners.MaxOutputBytes = 512 << 20
	c.Scanners.Tools = map[string]Tool{}
	c.Scanners.Sandbox.Backend = "auto"
	c.Limits.MaxLayers = 256
	c.Limits.MaxLayerBytes = 4 << 30
	c.Limits.MaxTotalBytes = 16 << 30
	c.Limits.MaxScratchBytes = 32 << 30
	c.Limits.MinFreeDiskBytes = 2 << 30
	c.Health.DBMaxAge = Duration{72 * time.Hour}
	c.Health.MonitorInterval = Duration{24 * time.Hour}
	c.SLA.Profile = "standard"
	c.Decisions.VendorDependencyMaxDays = 30
	c.Decisions.OperationalRequirementMaxDays = 365
	c.Notifications.DueSoonDays = 7
	return c
}

func defaultDataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "shieldmon")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", "shieldmon")
	}
	return "shieldmon-data"
}

// Load reads path over the defaults. A missing file at the default location
// is not an error; an explicitly given missing file is.
func Load(path string, explicit bool) (Config, error) {
	c := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return c, nil
		}
		return c, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if rest, ok := strings.CutPrefix(c.DataDir, "~/"); ok {
		if h, err := os.UserHomeDir(); err == nil {
			c.DataDir = filepath.Join(h, rest)
		}
	}
	return c, c.Validate()
}

// Validate checks semantic constraints.
func (c Config) Validate() error {
	if _, err := model.ParsePlatform(c.Platform); err != nil {
		return err
	}
	if len(c.Scanners.Matchers) == 0 {
		return fmt.Errorf("scanners.matchers: at least one matcher is required")
	}
	if _, err := SLAProfile(c.SLA.Profile, c.SLA.Days); err != nil {
		return err
	}
	if c.Decisions.VendorDependencyMaxDays <= 0 || c.Decisions.OperationalRequirementMaxDays <= 0 {
		return fmt.Errorf("decisions: max days must be positive")
	}
	if c.Notifications.DueSoonDays < 0 {
		return fmt.Errorf("notifications.due_soon_days must not be negative (0 disables sla_due_soon)")
	}
	if c.Limits.MaxScratchBytes < 0 || c.Limits.MinFreeDiskBytes < 0 {
		return fmt.Errorf("limits: max_scratch_bytes and min_free_disk_bytes must not be negative (0 disables)")
	}
	return nil
}

// DefaultPath returns the default config file location.
func DefaultPath() string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "shieldmon", "config.yaml")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "shieldmon", "config.yaml")
	}
	return "shieldmon.yaml"
}

// SLA maps severities to remediation deadlines in days. Zero means no SLA.
type SLA map[model.Severity]int

// slaProfiles are the built-in remediation deadlines, in days from first
// detection. Organizations map their own policy with sla.days overrides.
var slaProfiles = map[string]SLA{
	"standard": {model.SeverityCritical: 30, model.SeverityHigh: 30, model.SeverityMedium: 90, model.SeverityLow: 180},
	"strict":   {model.SeverityCritical: 15, model.SeverityHigh: 30, model.SeverityMedium: 90, model.SeverityLow: 180},
}

// SLAProfile returns a named profile with per-severity overrides applied.
func SLAProfile(name string, overrides map[string]int) (SLA, error) {
	base, ok := slaProfiles[name]
	if !ok {
		return nil, fmt.Errorf("sla.profile: unknown profile %q (supported: standard, strict)", name)
	}
	out := SLA{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overrides {
		sev := model.ParseSeverity(k)
		if sev == model.SeverityUnknown || v < 0 {
			return nil, fmt.Errorf("sla.days: invalid entry %s: %d", k, v)
		}
		out[sev] = v
	}
	return out, nil
}

// Template is written by `shieldmon init`.
const Template = `# ShieldMon configuration. All keys are optional; defaults shown.
# data_dir: ~/.local/share/shieldmon
platform: linux/amd64

scanners:
  # Each matcher implies its SBOM generator: grype -> syft, trivy -> trivy.
  matchers: [grype, trivy]
  timeout: 30m
  max_output_bytes: 536870912
  # Per-plugin settings. Pin binaries by SHA-256 ('shieldmon doctor' prints
  # current values); a mismatch aborts the scan and opens a health finding.
  # Scanners never download DBs while scanning: 'shieldmon db update' (run first by
  # monitor, scan and rematch) refreshes them. Set db_auto_update: false (grype) or
  # skip_db_update: true (trivy) when the DBs are managed out of band.
  tools:
    syft:  { path: "", sha256: "" }
    grype: { path: "", sha256: "", options: { db_auto_update: true } }
    trivy: { path: "", sha256: "", options: { skip_db_update: false, offline_scan: false } }
  # Confinement for scanner processes, which parse hostile image content:
  #   bwrap     Linux hosts with bubblewrap installed (Ubuntu >= 23.10 also needs the
  #             AppArmor profile from deploy/apparmor/README.md)
  #   landlock  containers and hosts without user namespaces (Linux >= 5.19 with the
  #             Landlock LSM enabled)
  #   auto      bwrap, else landlock, else refuse to scan (the default)
  #   none      no confinement (keeps a scanner_unsandboxed health finding open);
  #             for development hosts without a backend, such as macOS
  # 'shieldmon plugins' lists the backends and whether they run here
  # (docs/adr/0011-scanner-sandbox.md).
  # Scanner DBs and caches live in <data_dir>/cache.
  sandbox:
    backend: auto

limits:
  max_layers: 256
  max_layer_bytes: 4294967296
  max_total_bytes: 17179869184
  # Bounds on scanner processes, which may unpack layers to far more than they download:
  # scratch space of one process (also the size of any file it writes while reading
  # image content),
  # and free space left on the data dir's disk. A breach kills the scanner and fails the
  # scan with a health finding. 0 disables a bound.
  max_scratch_bytes: 34359738368
  min_free_disk_bytes: 2147483648

health:
  db_max_age: 72h        # older vulnerability DBs open a db_stale health finding
  monitor_interval: 24h  # a gap > 1.5x opens a monitor_missed health finding

sla:
  # Remediation deadlines in days from first detection.
  #   standard: critical 30, high 30, medium 90, low 180
  #   strict:   critical 15, high 30, medium 90, low 180
  profile: standard
  # days: { critical: 30, high: 30, medium: 90, low: 180 }   # per-severity overrides

decisions:
  # A plain risk acceptance never outlives the SLA deadline. Beyond it you need
  # a deviation: vendor-dependency (no fix exists; reviewed every N days, reopens
  # when a fix ships) or operational-requirement (fix exists, cannot be applied).
  vendor_dependency_max_days: 30
  operational_requirement_max_days: 365

# Registry credentials and listing (docs/processes/registries.md). Without rules, the
# built-in providers apply in this order: docker config and credential helpers, Amazon
# ECR through the AWS default chain, Google ADC; everything else is anonymous. Rules come
# first. Options never hold a credential: they name environment variables (*_env).
registries: []
# - hosts: [registry.gitlab.example.com]
#   provider: gitlab
#   options: { api_url: https://gitlab.example.com, token_env: CI_JOB_TOKEN }

# Notifications after each 'shieldmon monitor' cycle (docs/processes/notifications.md).
# Events: finding_new_kev, finding_new_critical, sla_breached, sla_due_soon, health_opened
# (all when events is omitted). Each event reaches a channel once; digest: true sends one
# summary per cycle. 'shieldmon plugins' lists the notifiers and their options; options
# never hold a credential: they name environment variables (*_env).
notifications:
  due_soon_days: 7
  channels: []
  # - name: secops
  #   notifier: webhook
  #   events: [finding_new_kev, finding_new_critical, sla_breached, health_opened]
  #   options: { url: https://hooks.example.com/shieldmon, secret_env: SHIELDMON_WEBHOOK_SECRET }
  # - name: secops-mail
  #   notifier: smtp
  #   digest: true
  #   options: { host: smtp.example.com, from: shieldmon@example.com, to: [secops@example.com],
  #              username: shieldmon, password_env: SHIELDMON_SMTP_PASSWORD }
`

// Policy builds the decision policy from configuration.
func (c Config) Policy() (lifecycle.Policy, error) {
	sla, err := SLAProfile(c.SLA.Profile, c.SLA.Days)
	if err != nil {
		return lifecycle.Policy{}, err
	}
	return lifecycle.Policy{
		Profile:                       c.SLA.Profile,
		SLADays:                       sla,
		VendorDependencyMaxDays:       c.Decisions.VendorDependencyMaxDays,
		OperationalRequirementMaxDays: c.Decisions.OperationalRequirementMaxDays,
	}, nil
}
