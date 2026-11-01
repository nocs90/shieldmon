// Package charts finds the versions of Helm charts and downloads their archives from chart
// sources: HTTP chart repositories, OCI registries and Artifact Hub
// (docs/adr/0032-chart-sources.md). Sources are an extension point: interface, registry and
// conformance kit (chartstest), like scanners and registry providers. Everything a source
// returns is hostile input: indexes and archives are bounded, archives are checked before
// anything renders them, and nothing in them is executed here.
package charts

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits on what a source may return.
const (
	MaxIndexBytes   = 32 << 20
	MaxArchiveBytes = 16 << 20
	MaxVersions     = 1000
)

// Version is one released version of a chart.
type Version struct {
	Version    string    `json:"version"`
	AppVersion string    `json:"app_version,omitempty"`
	Created    time.Time `json:"created,omitzero"`
	// Digest identifies the archive when the source says so before downloading it
	// (sha256:… of the archive in an HTTP index, the manifest digest in a registry).
	Digest     string `json:"digest,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty"`
}

// Source lists and fetches the versions of the charts it holds.
type Source interface {
	// Versions returns the chart's versions, newest first, at most MaxVersions.
	Versions(ctx context.Context, chart string) ([]Version, error)
	// Fetch writes the archive of one version to w, at most MaxArchiveBytes, and returns
	// its digest (sha256:… of the archive, or the manifest digest in a registry).
	Fetch(ctx context.Context, chart, version string, w io.Writer) (string, error)
	// Location names where the chart comes from, for reports (a URL or a repository).
	Location(chart string) string
}

// Spec is what a source receives at construction.
type Spec struct {
	Options Options
	// Client fetches what the configuration names over HTTPS (HTTP repositories, Artifact
	// Hub). Nil: a default bounded one.
	Client *http.Client
	// Public fetches what remote content names (archive URLs on other hosts, repositories
	// Artifact Hub points to): public addresses only. Nil: PublicClient().
	Public *http.Client
	// Derived marks options taken from remote content rather than the configuration: https
	// and public addresses only.
	Derived bool
	// OCI lists and fetches charts in registries through internal/oci, where registry
	// credentials stay (the CLI wires it).
	OCI OCI
}

// OCI is the registry access a source may use.
type OCI interface {
	// Tags lists at most limit tags of repository.
	Tags(ctx context.Context, repository string, limit int) ([]string, error)
	// Fetch writes the chart archive of ref (repository:tag) to w and returns the manifest digest.
	Fetch(ctx context.Context, ref string, maxBytes int64, w io.Writer) (string, error)
}

// Options are a source's settings from configuration.
type Options map[string]any

// String returns a string option or def when unset.
func (o Options) String(key, def string) (string, error) {
	v, ok := o[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("option %s: want a string, got %T", key, v)
	}
	return s, nil
}

// Plugin describes a source; sources register themselves from an init function.
type Plugin struct {
	Name        string
	Description string
	// Options lists the accepted option keys; anything else is a configuration error.
	Options []string
	New     func(Spec) (Source, error)
}

var (
	mu      sync.RWMutex
	plugins = map[string]Plugin{}
)

// Register makes a source available. It panics on duplicate or invalid registrations.
func Register(p Plugin) {
	mu.Lock()
	defer mu.Unlock()
	if p.Name == "" || p.New == nil {
		panic("charts: Register requires Name and New")
	}
	if _, dup := plugins[p.Name]; dup {
		panic("charts: duplicate source " + p.Name)
	}
	plugins[p.Name] = p
}

// Lookup returns a registered source plugin.
func Lookup(name string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// Plugins returns every registered source, sorted by name.
func Plugins() []Plugin {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// New builds the source plugin name with spec, refusing unknown options.
func New(name string, spec Spec) (Source, error) {
	p, ok := Lookup(name)
	if !ok {
		names := make([]string, 0)
		for _, q := range Plugins() {
			names = append(names, q.Name)
		}
		return nil, fmt.Errorf("unknown chart source %q (registered: %s)", name, strings.Join(names, ", "))
	}
	for k := range spec.Options {
		if !slices.Contains(p.Options, k) {
			return nil, fmt.Errorf("chart source %s: unknown option %q (known: %s)", name, k, strings.Join(p.Options, ", "))
		}
	}
	if spec.Client == nil {
		spec.Client = DefaultClient()
	}
	return p.New(spec)
}

// DefaultClient fetches what the configuration names, following at most 5 redirects, all
// HTTPS: chart repositories commonly redirect to object storage (GitHub Pages, releases).
func DefaultClient() *http.Client {
	return &http.Client{Timeout: 2 * time.Minute, CheckRedirect: httpsRedirects}
}
