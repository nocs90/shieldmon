package charts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"github.com/nocs90/shieldmon/internal/manifests"
	"github.com/nocs90/shieldmon/internal/scanner"
)

// Limits on the values one profile renders with: they come from the configuration, but are
// copied for every render.
const (
	MaxValuesBytes = 4 << 20
	MaxValuesFiles = 32
	MaxAPIVersions = 200
)

// Profile is one way a chart is installed: the release, its namespace and its values
// (docs/adr/0033-chart-rendering.md). The images a chart runs depend on its values (an
// optional sidecar, a registry mirror), so a chart is followed per profile.
type Profile struct {
	Name      string
	Release   string
	Namespace string
	// Values are YAML documents, applied in order (later ones win), like helm's -f.
	Values [][]byte
	// KubeVersion and APIVersions set what templates see as .Capabilities: helm template
	// talks to no cluster.
	KubeVersion string
	APIVersions []string
	// SkipSchemaValidation skips the chart's values.schema.json: a schema that refers to
	// remote schemas cannot load without network.
	SkipSchemaValidation bool
}

var (
	// releaseName is Helm's own rule for release names.
	releaseName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
	namespace   = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	kubeVersion = regexp.MustCompile(`^v?[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]{1,3})?$`)
	// apiVersion is group/version or group/version/Kind, as helm's --api-versions takes it.
	apiVersion = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})(/[A-Za-z0-9][A-Za-z0-9.-]{0,62}){0,2}$`)
)

// Check validates a profile. Every value reaches helm as one --flag=value argument.
func (p Profile) Check() error {
	switch {
	case len(p.Release) > 53 || !releaseName.MatchString(p.Release):
		return fmt.Errorf("release %q: lowercase letters, digits, '-' and '.', at most 53", truncate(p.Release))
	case !namespace.MatchString(p.Namespace):
		return fmt.Errorf("namespace %q: lowercase letters, digits and '-', at most 63", truncate(p.Namespace))
	case p.KubeVersion != "" && !kubeVersion.MatchString(p.KubeVersion):
		return fmt.Errorf("kube_version %q: want a version such as 1.33 or v1.33.2", truncate(p.KubeVersion))
	case len(p.APIVersions) > MaxAPIVersions:
		return fmt.Errorf("api_versions: at most %d", MaxAPIVersions)
	case len(p.Values) > MaxValuesFiles:
		return fmt.Errorf("values: at most %d documents", MaxValuesFiles)
	}
	for _, a := range p.APIVersions {
		if !apiVersion.MatchString(a) {
			return fmt.Errorf("api_versions %q: want group/version or group/version/Kind", truncate(a))
		}
	}
	total := 0
	for _, v := range p.Values {
		total += len(v)
	}
	if total > MaxValuesBytes {
		return fmt.Errorf("values: %d bytes, at most %d", total, MaxValuesBytes)
	}
	return nil
}

// Renderer renders chart archives with a pinned helm (`helm template`), confined like the
// scanners: no network, no files but the archive and the values, a private scratch directory
// as its home, bounded time and output (docs/adr/0033-chart-rendering.md). Templates of a
// third-party chart are code: they run nowhere else.
type Renderer struct {
	// Helm is the helm executable, resolved and checksum-verified.
	Helm string
	// Runner confines helm. Render takes the network and the scanners' DB cache away and
	// bounds the output to what the manifest parser reads.
	Runner scanner.Runner
	// StageDir holds a private directory per render with the archive and the values,
	// removed when helm exits.
	StageDir string
}

// helmEnv makes helm keep its configuration, cache and plugins (none) in its scratch home,
// whatever the environment names.
var helmEnv = []string{"XDG_CACHE_HOME=", "XDG_CONFIG_HOME=", "XDG_DATA_HOME="}

// Render checks archive as the version of chart it claims to be, renders it with profile p
// and returns the images the rendered manifests run. The manifests are hostile input too:
// they go through the manifest parser's bounds.
func (r Renderer) Render(ctx context.Context, archive []byte, chart, version string, p Profile) (manifests.Result, error) {
	if r.Helm == "" || r.StageDir == "" {
		return manifests.Result{}, errors.New("charts: renderer without helm or staging directory")
	}
	if r.Runner.Sandbox == nil || r.Runner.TempDir == "" {
		// A nil sandbox runs unconfined, and without TempDir helm has no private home; the
		// CLI always passes the scanners' (ADR 0011).
		return manifests.Result{}, errors.New("charts: renderer without a sandbox or scratch space")
	}
	if _, err := CheckArchive(archive, chart, version); err != nil {
		return manifests.Result{}, err
	}
	if err := p.Check(); err != nil {
		return manifests.Result{}, fmt.Errorf("profile %s: %w", p.Name, err)
	}
	if err := os.MkdirAll(r.StageDir, 0o700); err != nil {
		return manifests.Result{}, err
	}
	dir, err := os.MkdirTemp(r.StageDir, "chart-")
	if err != nil {
		return manifests.Result{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "chart.tgz")
	if err := os.WriteFile(path, archive, 0o600); err != nil {
		return manifests.Result{}, err
	}
	args := []string{"template", "--namespace=" + p.Namespace}
	for i, v := range p.Values {
		name := filepath.Join(dir, "values-"+strconv.Itoa(i)+".yaml")
		if err := os.WriteFile(name, v, 0o600); err != nil {
			return manifests.Result{}, err
		}
		args = append(args, "--values="+name)
	}
	if p.KubeVersion != "" {
		args = append(args, "--kube-version="+p.KubeVersion)
	}
	for _, a := range p.APIVersions {
		args = append(args, "--api-versions="+a)
	}
	if p.SkipSchemaValidation {
		args = append(args, "--skip-schema-validation")
	}
	args = append(args, "--", p.Release, path)

	run := r.Runner
	run.CacheDir = ""
	run.MaxOutput = manifests.MaxBytes
	run.ExtraEnv = append(slices.Clone(run.ExtraEnv), helmEnv...)
	ctx = scanner.WithPolicy(ctx, scanner.Policy{ReadOnly: []string{dir}})
	out, err := run.Run(ctx, r.Helm, args...)
	if err != nil {
		return manifests.Result{}, fmt.Errorf("helm template %s %s (profile %s): %w", chart, version, p.Name, err)
	}
	res, err := manifests.Parse(bytes.NewReader(out))
	if err != nil {
		return manifests.Result{}, fmt.Errorf("rendered %s %s (profile %s): %w", chart, version, p.Name, err)
	}
	return res, nil
}
