// Package enrich adds facts about vulnerabilities that scanners do not reliably report, such
// as membership of the CISA Known Exploited Vulnerabilities catalog (docs/adr/0019-enrichers.md).
// Enrichers are plugins: each keeps its data in a cache directory, refreshes it on Update (the
// only step with network), and enriches matches from that data on every scan.
package enrich

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/redact"
)

// Enricher adds facts to matches from data it refreshes on Update.
type Enricher interface {
	// Update refreshes the data from its source. On failure the data in use is kept.
	Update(ctx context.Context) error
	// UpdatedAt is when the data in use was last confirmed current by its source (zero: none).
	UpdatedAt() time.Time
	// Enrich adds what the enricher knows to m. It uses only loaded data: no I/O.
	Enrich(m *model.Match)
}

// Plugin describes an enricher. Enrichers register themselves from an init function, like the
// other extension points (ADR 0008).
type Plugin struct {
	Name        string
	Description string
	// Options lists the keys accepted under enrichers.<name>.options.
	Options []string
	// Default is true for enrichers enabled without configuration.
	Default bool
	New     func(Spec) (Enricher, error)
}

// Spec is what an enricher receives at construction time.
type Spec struct {
	// CacheDir is the enricher's own directory for its data (created, owner-only).
	CacheDir string
	Options  map[string]any
	// Transport carries HTTP requests; http.DefaultTransport unless a test replaces it.
	Transport http.RoundTripper
	// Now is the clock; time.Now unless a test replaces it.
	Now func() time.Time
}

// String returns a string option or def when unset.
func (s Spec) String(key, def string) (string, error) {
	v, ok := s.Options[key]
	if !ok {
		return def, nil
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("option %s: want a string, got %T", key, v)
	}
	return str, nil
}

func (s Spec) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

var (
	pluginsMu sync.RWMutex
	plugins   = map[string]Plugin{}
)

// Register makes an enricher available. It panics on duplicate or invalid registrations.
func Register(p Plugin) {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	if p.Name == "" || p.Description == "" || p.New == nil {
		panic("enrich: Register requires Name, Description and New")
	}
	if _, dup := plugins[p.Name]; dup {
		panic("enrich: duplicate enricher " + p.Name)
	}
	plugins[p.Name] = p
}

// Plugins returns the registered enrichers sorted by name.
func Plugins() []Plugin {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup returns a registered enricher.
func Lookup(name string) (Plugin, bool) {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// Config is one enricher's configuration (enrichers.<name>).
type Config struct {
	Enabled *bool
	// MaxAge is how old the data may get before an enrichment_stale health finding (0: never).
	MaxAge  time.Duration
	Options map[string]any
}

// Instance is a configured, constructed enricher.
type Instance struct {
	Name     string
	MaxAge   time.Duration
	Enricher Enricher
}

// New builds the enabled enrichers: the defaults unless configured off, plus those enabled by
// configuration, in name order. cacheRoot holds one directory per enricher.
func New(cfgs map[string]Config, cacheRoot string, base Spec) ([]Instance, error) {
	for name := range cfgs {
		if _, ok := Lookup(name); !ok {
			return nil, fmt.Errorf("enrichers.%s: unknown enricher (registered: %s)", name, names())
		}
	}
	var out []Instance
	for _, p := range Plugins() {
		c, configured := cfgs[p.Name]
		enabled := p.Default
		if configured && c.Enabled != nil {
			enabled = *c.Enabled
		}
		if !enabled {
			continue
		}
		for k, v := range c.Options {
			if !slices.Contains(p.Options, k) {
				return nil, fmt.Errorf("enrichers.%s.options: unknown option %q (known: %s)", p.Name, k, strings.Join(p.Options, ", "))
			}
			if s, ok := v.(string); ok && redact.String(s) != s {
				return nil, fmt.Errorf("enrichers.%s.options: option %s looks like a credential", p.Name, k)
			}
		}
		spec := base
		spec.Options = c.Options
		spec.CacheDir = cacheRoot + string(os.PathSeparator) + p.Name
		if err := os.MkdirAll(spec.CacheDir, 0o700); err != nil {
			return nil, err
		}
		inst, err := p.New(spec)
		if err != nil {
			return nil, fmt.Errorf("enrichers.%s: %s", p.Name, redact.Error(err))
		}
		out = append(out, Instance{Name: p.Name, MaxAge: c.MaxAge, Enricher: inst})
	}
	return out, nil
}

func names() string {
	var out []string
	for _, p := range Plugins() {
		out = append(out, p.Name)
	}
	return strings.Join(out, ", ")
}
