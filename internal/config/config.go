// Package config loads ShieldMon's YAML configuration.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/nocs90/shieldmon/internal/charts"
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
	Name     string   `yaml:"name"`
	Notifier string   `yaml:"notifier"`
	Events   []string `yaml:"events,omitempty"`
	Digest   bool     `yaml:"digest,omitempty"`
	// Owners, when set, limit the channel to the events of these teams' targets.
	Owners  []string       `yaml:"owners,omitempty"`
	Options map[string]any `yaml:"options,omitempty"`
}

// Export configures one exporter (docs/adr/0027-exporters.md). Options never hold a
// credential: they name environment variables (*_env).
type Export struct {
	Name     string         `yaml:"name"`
	Exporter string         `yaml:"exporter"`
	Options  map[string]any `yaml:"options,omitempty"`
}

// Owner is a team owning the targets its patterns match (docs/adr/0024-ownership.md).
type Owner struct {
	Team    string   `yaml:"team"`
	Contact string   `yaml:"contact,omitempty"`
	Targets []string `yaml:"targets"`
}

// Enricher configures one enricher (docs/adr/0019-enrichers.md). Options never hold a
// credential.
type Enricher struct {
	// Enabled turns an enricher on or off; unset keeps its default (kev: on).
	Enabled *bool `yaml:"enabled,omitempty"`
	// MaxAge is how old its data may get before enrichment_stale (0: the default, 72h).
	MaxAge  Duration       `yaml:"max_age,omitempty"`
	Options map[string]any `yaml:"options,omitempty"`
}

// DefaultEnrichMaxAge is the data age that opens enrichment_stale when none is configured.
const DefaultEnrichMaxAge = 72 * time.Hour

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
		// Concurrency is how many targets monitor scans at once
		// (docs/adr/0026-concurrent-monitoring.md); memory and scratch space scale with it.
		Concurrency int `yaml:"concurrency"`
	} `yaml:"scanners"`

	Limits struct {
		MaxLayers     int   `yaml:"max_layers"`
		MaxLayerBytes int64 `yaml:"max_layer_bytes"`
		MaxTotalBytes int64 `yaml:"max_total_bytes"`
		// MaxScratchBytes bounds what one scanner process unpacks into its scratch space.
		MaxScratchBytes int64 `yaml:"max_scratch_bytes"`
		// MinFreeDiskBytes stops a scanner before the data dir's disk fills up.
		MinFreeDiskBytes int64 `yaml:"min_free_disk_bytes"`
		// RegistryRPS bounds the monitoring cycle's requests per registry host per second
		// (bursts of as many; 0: unlimited).
		RegistryRPS float64 `yaml:"registry_rps"`
	} `yaml:"limits"`

	Health struct {
		DBMaxAge        Duration `yaml:"db_max_age"`
		MonitorInterval Duration `yaml:"monitor_interval"`
		// AuditVerifyInterval is how often monitor verifies the audit chain (ADR 0018).
		AuditVerifyInterval Duration `yaml:"audit_verify_interval"`
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

	// Enrichers add facts to findings, refreshed with the vulnerability DBs.
	Enrichers map[string]Enricher `yaml:"enrichers,omitempty"`

	// Notifications are sent after each monitoring cycle (docs/adr/0015-notifications.md).
	Notifications struct {
		DueSoonDays int       `yaml:"due_soon_days"`
		Channels    []Channel `yaml:"channels,omitempty"`
	} `yaml:"notifications"`

	// Gate is the policy of 'shieldmon gate' (docs/adr/0021-policy-gate.md).
	Gate Gate `yaml:"gate"`

	// Exports hand results to portfolio tools (docs/adr/0027-exporters.md); validated by
	// export.New.
	Exports []Export `yaml:"exports,omitempty"`

	// Owners are the teams owning targets, first match wins (docs/adr/0024-ownership.md);
	// validated by owners.New.
	Owners []Owner `yaml:"owners,omitempty"`

	// Bases are the base images targets are built on (docs/adr/0022-base-image-lineage.md).
	Bases struct {
		// MaxAge is how long a base may stay unchanged before it is unmaintained (0: never).
		MaxAge Duration `yaml:"max_age"`
		// Successors name the maintained base to move to (docs/adr/0025-base-successors.md);
		// validated by lineage.NewSuccessors.
		Successors []Successor `yaml:"successors,omitempty"`
	} `yaml:"bases"`

	// Charts are the Helm charts followed (docs/adr/0032-chart-sources.md); sources and
	// options are validated by charts.New.
	Charts []Chart `yaml:"charts,omitempty"`

	// Helm renders charts (docs/adr/0033-chart-rendering.md): the binary
	// scripts/install-scanners.sh installs, run in the scanners' sandbox.
	Helm struct {
		Path    string   `yaml:"path,omitempty"`
		SHA256  string   `yaml:"sha256,omitempty"`
		Timeout Duration `yaml:"timeout"`
	} `yaml:"helm"`

	// Runtime is where images run, from cluster exports (docs/adr/0029-runtime-context.md).
	Runtime struct {
		// Inventories are `kubectl get pods,services,ingresses,httproutes -A -o json` files,
		// one per cluster.
		Inventories []RuntimeInventory `yaml:"inventories,omitempty"`
		// MaxAge is how old an export may be before it is ignored (0: no limit).
		MaxAge Duration `yaml:"max_age"`
	} `yaml:"runtime"`
}

// chartID bounds the names charts are known by in ShieldMon.
var chartID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,99}$`)

// ID is the name the chart is known by in ShieldMon.
func (c Chart) ID() string {
	if c.Name != "" {
		return c.Name
	}
	return c.Chart
}

// clusterName bounds cluster names, which appear in reports and priority reasons.
var clusterName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// Chart is one followed Helm chart: Name identifies it in ShieldMon (default the chart's
// name), Chart is its name in the source.
type Chart struct {
	Name    string         `yaml:"name"`
	Chart   string         `yaml:"chart"`
	Source  string         `yaml:"source"`
	Options map[string]any `yaml:"options,omitempty"`
	// Profiles are the ways the chart is installed, each rendered on its own; none: one,
	// "default", with the chart's own values.
	Profiles []ChartProfile `yaml:"profiles,omitempty"`
}

// ChartProfile is one installation of a chart: its release, namespace and values
// (docs/adr/0033-chart-rendering.md).
type ChartProfile struct {
	Name string `yaml:"name"`
	// Release defaults to the chart's name in ShieldMon, Namespace to "default".
	Release   string `yaml:"release,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	// ValuesFiles are applied in order, then Values: later ones win, like helm's -f.
	ValuesFiles          []string       `yaml:"values_files,omitempty"`
	Values               map[string]any `yaml:"values,omitempty"`
	KubeVersion          string         `yaml:"kube_version,omitempty"`
	APIVersions          []string       `yaml:"api_versions,omitempty"`
	SkipSchemaValidation bool           `yaml:"skip_schema_validation,omitempty"`
}

// RenderProfiles returns the chart's profiles with their defaults applied.
func (c Chart) RenderProfiles() []ChartProfile {
	ps := c.Profiles
	if len(ps) == 0 {
		ps = []ChartProfile{{Name: "default"}}
	}
	out := make([]ChartProfile, len(ps))
	for i, p := range ps {
		if p.Release == "" {
			p.Release = c.ID()
		}
		if p.Namespace == "" {
			p.Namespace = "default"
		}
		out[i] = p
	}
	return out
}

// RuntimeInventory is one cluster's export.
type RuntimeInventory struct {
	Cluster string `yaml:"cluster"`
	Path    string `yaml:"path"`
}

// Successor names the base that succeeds the bases matching From.
type Successor struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
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
	c.Limits.RegistryRPS = 10
	c.Scanners.Concurrency = 1
	c.Health.DBMaxAge = Duration{72 * time.Hour}
	c.Health.MonitorInterval = Duration{24 * time.Hour}
	c.Health.AuditVerifyInterval = Duration{24 * time.Hour}
	c.SLA.Profile = "standard"
	c.Decisions.VendorDependencyMaxDays = 30
	c.Decisions.OperationalRequirementMaxDays = 365
	c.Notifications.DueSoonDays = 7
	c.Gate = DefaultGate()
	c.Bases.MaxAge = Duration{90 * 24 * time.Hour}
	c.Runtime.MaxAge = Duration{48 * time.Hour}
	c.Helm.Timeout = Duration{2 * time.Minute}
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
	if err := c.validDecisions(); err != nil {
		return err
	}
	if c.Health.AuditVerifyInterval.Duration < 0 {
		return fmt.Errorf("health.audit_verify_interval must not be negative (0 disables)")
	}
	if c.Notifications.DueSoonDays < 0 {
		return fmt.Errorf("notifications.due_soon_days must not be negative (0 disables sla_due_soon)")
	}
	if c.Limits.MaxScratchBytes < 0 || c.Limits.MinFreeDiskBytes < 0 {
		return fmt.Errorf("limits: max_scratch_bytes and min_free_disk_bytes must not be negative (0 disables)")
	}
	if c.Scanners.Concurrency < 1 || c.Scanners.Concurrency > 64 {
		return fmt.Errorf("scanners.concurrency %d: want 1 to 64", c.Scanners.Concurrency)
	}
	if !(c.Limits.RegistryRPS >= 0) { // NaN too
		return fmt.Errorf("limits.registry_rps must not be negative (0: unlimited)")
	}
	if c.Runtime.MaxAge.Duration < 0 {
		return fmt.Errorf("runtime.max_age must not be negative (0: no limit)")
	}
	chartNames := map[string]bool{}
	for i, ch := range c.Charts {
		id := ch.Name
		if id == "" {
			id = ch.Chart
		}
		switch {
		case ch.Chart == "" || ch.Source == "":
			return fmt.Errorf("charts[%d]: chart and source are required", i)
		case !chartID.MatchString(id):
			return fmt.Errorf("charts[%d]: name %q: lowercase letters, digits, '.', '_', '-' (at most 100)", i, id)
		case chartNames[id]:
			return fmt.Errorf("charts[%d]: name %q is listed twice (give one a name:)", i, id)
		}
		chartNames[id] = true
		profiles := map[string]bool{}
		for j, p := range ch.RenderProfiles() {
			switch {
			case !chartID.MatchString(p.Name):
				return fmt.Errorf("charts[%d].profiles[%d]: name %q: lowercase letters, digits, '.', '_', '-' (at most 100)", i, j, p.Name)
			case profiles[p.Name]:
				return fmt.Errorf("charts[%d]: profile %q is listed twice", i, p.Name)
			case slices.Contains(p.ValuesFiles, "") || slices.Contains(p.ValuesFiles, "-"):
				return fmt.Errorf("charts[%d].profiles[%d]: values_files entries are file paths", i, j)
			}
			profiles[p.Name] = true
			// Values files are read when the chart renders; the rest is checked now.
			cp := charts.Profile{Release: p.Release, Namespace: p.Namespace, KubeVersion: p.KubeVersion, APIVersions: p.APIVersions}
			if err := cp.Check(); err != nil {
				return fmt.Errorf("charts[%d] %s profile %s: %w", i, id, p.Name, err)
			}
		}
	}
	if c.Helm.Timeout.Duration <= 0 {
		return fmt.Errorf("helm.timeout must be positive")
	}
	clusters := map[string]bool{}
	for i, inv := range c.Runtime.Inventories {
		switch {
		case !clusterName.MatchString(inv.Cluster):
			return fmt.Errorf("runtime.inventories[%d].cluster %q: want letters, digits, '.', '_' or '-' (at most 63)", i, inv.Cluster)
		case clusters[inv.Cluster]:
			return fmt.Errorf("runtime.inventories[%d]: cluster %q is listed twice", i, inv.Cluster)
		case inv.Path == "":
			return fmt.Errorf("runtime.inventories[%d].path is required", i)
		}
		clusters[inv.Cluster] = true
	}
	if c.Bases.MaxAge.Duration < 0 {
		return fmt.Errorf("bases.max_age must not be negative (0 disables base_unmaintained)")
	}
	return c.Gate.Validate()
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

// MaxPolicyDays bounds every deadline and decision limit: ten years is a typo, not a policy.
const MaxPolicyDays = 3650

// validDecisions checks the decision limits (docs/adr/0010-decision-policy.md): positive,
// bounded, and a vendor dependency's review period no longer than the longest operational
// requirement (it is the more frequently reviewed deviation).
func (c Config) validDecisions() error {
	v, o := c.Decisions.VendorDependencyMaxDays, c.Decisions.OperationalRequirementMaxDays
	switch {
	case v <= 0 || o <= 0:
		return fmt.Errorf("decisions: max days must be positive")
	case v > MaxPolicyDays || o > MaxPolicyDays:
		return fmt.Errorf("decisions: max days must not exceed %d", MaxPolicyDays)
	case v > o:
		return fmt.Errorf("decisions: vendor_dependency_max_days (%d) is a review period and must not exceed operational_requirement_max_days (%d)", v, o)
	}
	return nil
}

// severityOrder lists the severities that can have a deadline, most severe first.
var severityOrder = []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityNegligible}

// Validate rejects incoherent deadlines (docs/adr/0016-remediation-timeframes.md): each at
// most MaxPolicyDays, and a more severe finding never gets more time than a less severe one,
// nor none while a less severe one has a deadline.
func (s SLA) Validate() error {
	for _, sev := range severityOrder {
		if d := s[sev]; d < 0 || d > MaxPolicyDays {
			return fmt.Errorf("sla: %s deadline %d days: want 0 (none) to %d", sev, d, MaxPolicyDays)
		}
	}
	for i, more := range severityOrder {
		for _, less := range severityOrder[i+1:] {
			dm, dl := s[more], s[less]
			switch {
			case dl > 0 && dm == 0:
				return fmt.Errorf("sla: %s has no deadline while %s has %d days: a more severe finding cannot get more time", more, less, dl)
			case dl > 0 && dm > dl:
				return fmt.Errorf("sla: %s deadline (%d days) is longer than %s (%d days): a more severe finding cannot get more time", more, dm, less, dl)
			}
		}
	}
	return nil
}

// SLAProfile returns a named profile with per-severity overrides applied, validated.
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
	if err := out.Validate(); err != nil {
		return nil, err
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
  # Targets 'shieldmon monitor' scans at once (--concurrency overrides). Each scan holds a
  # vulnerability DB in memory and up to max_total_bytes + max_scratch_bytes of disk: size
  # memory and the data dir's disk for that many (docs/adr/0026-concurrent-monitoring.md).
  concurrency: 1

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
  # Requests per second to each registry host during monitoring (resolve, fetch, inspect),
  # with bursts of as many; 0 is unlimited.
  registry_rps: 10

health:
  db_max_age: 72h        # older vulnerability DBs open a db_stale health finding
  monitor_interval: 24h  # a gap > 1.5x opens a monitor_missed health finding
  # monitor verifies the tamper-evident audit chain this often (0 disables; failures open
  # audit_chain_broken). Export digests too: 'shieldmon audit digest' (docs/processes/audit.md).
  audit_verify_interval: 24h

sla:
  # Remediation deadlines in days from first detection (docs/processes/remediation-policy.md).
  #   standard: critical 30, high 30, medium 90, low 180
  #   strict:   critical 15, high 30, medium 90, low 180
  # A more severe finding never gets more time than a less severe one; 0 is no deadline.
  profile: standard
  # days: { critical: 30, high: 30, medium: 90, low: 180, negligible: 0 }   # per-severity overrides

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

# Enrichers add facts scanners do not reliably report, refreshed with the vulnerability DBs
# (docs/processes/enrichment.md). kev (CISA Known Exploited Vulnerabilities) is on by
# default; without internet access, point it at a local copy or turn it off.
enrichers:
  kev:
    max_age: 72h           # older data opens an enrichment_stale health finding
    # enabled: false
    # options: { url: https://mirror.example.com/kev.json }   # or { file: /srv/kev.json }

# Notifications after each 'shieldmon monitor' cycle (docs/processes/notifications.md).
# Events: finding_new_kev, finding_new_critical, sla_breached, sla_due_soon, health_opened
# (all of these when events is omitted), and the opt-in finding_fixed (github-issues and
# gitlab-issues default to it), base_rebuild_available and base_unmaintained (base images,
# docs/processes/base-images.md). Each event reaches a channel once; digest: true sends one
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

# Policy of 'shieldmon gate IMAGE' in CI (docs/processes/ci-gate.md): pass, warn, fail or
# indeterminate. A finding is flagged by the strongest action of the rules whose conditions
# all hold: severity, cvss, epss, priority (minimums), age_days, kev, fixable, sla_breached.
# Findings are exempt only by a decision in force (accept-risk, not-affected, VEX); there is
# no ignore list. Without complete, fresh evidence a gate with no violation is indeterminate.
gate:
  rules:
    - { name: exploited, action: fail, when: { kev: true } }
    - { name: critical, action: fail, when: { severity: critical } }
    - { name: past-deadline, action: fail, when: { sla_breached: true } }
    - { name: high, action: warn, when: { severity: high } }
  exempt: [not_affected, risk_accepted]
  # max_db_age: 72h       # default: health.db_max_age
  max_evidence_age: 24h   # with --no-scan, the latest scan may be this old
  exit_codes: { warn: 0, fail: 2, indeterminate: 3 }   # errors exit 1

# Exports to portfolio tools, sent by 'shieldmon export' (docs/processes/exports.md). Options
# never hold a credential: they name environment variables (*_env).
exports: []
# - { name: dtrack, exporter: dependency-track, options: { url: https://dtrack.example.com, api_key_env: SHIELDMON_DTRACK_KEY } }
# - { name: dojo, exporter: defectdojo, options: { url: https://defectdojo.example.com, api_key_env: SHIELDMON_DOJO_KEY } }

# Teams owning targets (docs/processes/ownership.md): the first team with a pattern matching
# a target's reference or repository owns it ('*' stays within a path segment). Reports and
# the remediation plan show owners; a channel with 'owners: [team]' hears only their images.
owners: []
# - team: payments
#   contact: payments-security@example.com
#   targets: ["registry.example.com/payments/*"]

# Base images (docs/processes/base-images.md): each target's base comes from
# 'targets set-base' or the org.opencontainers.image.base.name annotation, and is proven by
# shared layers. monitor follows each base tag: a base unchanged for longer than max_age is
# unmaintained, and rebuilding on it fixes nothing.
bases:
  max_age: 2160h   # 90 days; 0 disables
  # The maintained base to move to when one is unmaintained, followed but never fetched
  # (first match wins; 'from' is a reference pattern like owners' targets).
  successors: []
  # - { from: "registry.access.redhat.com/ubi9/nodejs-20-minimal", to: "registry.access.redhat.com/ubi9/nodejs-22-minimal:latest" }

# Where images run (docs/processes/runtime-context.md): read-only cluster exports, written by
# a scheduled job with view rights, e.g.
#   kubectl get pods,services,ingresses,httproutes -A -o json > /var/lib/shieldmon/runtime/prod.json
# Findings of running images rank higher, of exposed ones higher still; nothing else changes.
runtime:
  max_age: 48h     # an older export is left out, with a warning; 0: no limit
  inventories: []
  # - { cluster: prod, path: /var/lib/shieldmon/runtime/prod.json }

# Helm charts followed (docs/processes/charts.md): sources are http (a chart repository's
# index.yaml), oci (a registry, with the registries' credentials) and artifacthub. 'shieldmon
# plugins' lists them.
charts: []
  # - { chart: ingress-nginx, source: http, options: { url: https://kubernetes.github.io/ingress-nginx } }
  # - { chart: nginx, source: oci, options: { repository: registry-1.docker.io/bitnamicharts } }
  # - { name: podinfo, chart: podinfo, source: artifacthub, options: { repository: podinfo } }
  # Each profile is one installation, rendered on its own with 'helm template' in the
  # scanners' sandbox (no network, only the archive and the values); none: the chart's defaults.
  # - chart: ingress-nginx
  #   source: http
  #   options: { url: https://kubernetes.github.io/ingress-nginx }
  #   profiles:
  #     - { name: prod, namespace: ingress, values_files: [/etc/shieldmon/values/ingress-prod.yaml] }
  #     - { name: mirror, values: { global: { image: { registry: mirror.example.com } } }, kube_version: "1.33" }

# The helm that renders charts: scripts/install-scanners.sh installs a pinned, signature-verified
# one. Pin it by SHA-256 like the scanners.
helm:
  path: ""
  sha256: ""
  timeout: 2m
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
