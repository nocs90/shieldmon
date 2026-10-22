package scanner

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Plugin describes a scanner adapter. Adapters register themselves from an
// init function (like database/sql drivers); the engine only ever sees the
// Generator and Matcher interfaces. See docs/extending/scanner-adapter.md.
type Plugin struct {
	// Name is the stable identifier used in configuration, e.g. "grype".
	Name string
	// Description is shown by `shieldmon plugins`.
	Description string
	// Options lists the option keys the plugin accepts under
	// scanners.tools.<name>.options; anything else is a configuration error.
	Options []string
	// New builds an instance. It must return a value implementing Generator,
	// Matcher, or both (one instance serves both roles).
	New func(Spec) (any, error)
}

// Spec is everything a plugin receives at construction time.
type Spec struct {
	Bin     Binary
	Runner  Runner
	Options Options
}

// Options are plugin-specific settings from configuration.
type Options map[string]any

// Bool returns a boolean option or def when unset.
func (o Options) Bool(key string, def bool) (bool, error) {
	v, ok := o[key]
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("option %s: want a boolean, got %T", key, v)
	}
	return b, nil
}

var (
	mu      sync.RWMutex
	plugins = map[string]Plugin{}
)

// Register makes a plugin available. It panics on duplicate or invalid
// registrations, which are programming errors.
func Register(p Plugin) {
	mu.Lock()
	defer mu.Unlock()
	if p.Name == "" || p.New == nil {
		panic("scanner: Register requires Name and New")
	}
	if _, dup := plugins[p.Name]; dup {
		panic("scanner: duplicate plugin " + p.Name)
	}
	plugins[p.Name] = p
}

// Lookup returns a registered plugin.
func Lookup(name string) (Plugin, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// Plugins returns all registered plugins sorted by name.
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

// Build instantiates the named matchers and the generators they require.
// specs supplies per-plugin settings; missing entries get defaults.
func Build(matchers []string, specs map[string]Spec, base Runner) (Set, error) {
	set := Set{Generators: map[string]Generator{}}
	instances := map[string]any{}
	instance := func(name string) (any, error) {
		if inst, ok := instances[name]; ok {
			return inst, nil
		}
		p, ok := Lookup(name)
		if !ok {
			return nil, fmt.Errorf("unknown scanner plugin %q (registered: %s)", name, strings.Join(names(), ", "))
		}
		spec, ok := specs[name]
		if !ok {
			spec = Spec{Runner: base}
		}
		if spec.Bin.Name == "" {
			spec.Bin.Name = name
		}
		for k := range spec.Options {
			if !slices.Contains(p.Options, k) {
				return nil, fmt.Errorf("scanners.tools.%s.options: unknown option %q (known: %s)", name, k, strings.Join(p.Options, ", "))
			}
		}
		inst, err := p.New(spec)
		if err != nil {
			return nil, fmt.Errorf("scanner plugin %s: %w", name, err)
		}
		instances[name] = inst
		return inst, nil
	}
	for _, name := range matchers {
		inst, err := instance(name)
		if err != nil {
			return Set{}, err
		}
		m, ok := inst.(Matcher)
		if !ok {
			return Set{}, fmt.Errorf("scanner plugin %s is not a matcher", name)
		}
		set.Matchers = append(set.Matchers, m)
		ginst, err := instance(m.Generator())
		if err != nil {
			return Set{}, fmt.Errorf("matcher %s needs generator %s: %w", name, m.Generator(), err)
		}
		g, ok := ginst.(Generator)
		if !ok {
			return Set{}, fmt.Errorf("matcher %s needs generator %s, which is not a generator", name, m.Generator())
		}
		set.Generators[g.Name()] = g
	}
	return set, nil
}

func names() []string {
	var out []string
	for _, p := range Plugins() {
		out = append(out, p.Name)
	}
	return out
}

func init() {
	Register(Plugin{
		Name:        "syft",
		Description: "Anchore Syft SBOM generator (CycloneDX + SPDX); feeds grype",
		New: func(s Spec) (any, error) {
			return &Syft{Bin: s.Bin, Runner: s.Runner}, nil
		},
	})
	Register(Plugin{
		Name:        "grype",
		Description: "Anchore Grype matcher on syft SBOMs",
		Options:     []string{"db_auto_update"},
		New: func(s Spec) (any, error) {
			auto, err := s.Options.Bool("db_auto_update", true)
			if err != nil {
				return nil, err
			}
			return &Grype{Bin: s.Bin, Runner: s.Runner, DBAutoUpdate: auto}, nil
		},
	})
	Register(Plugin{
		Name:        "trivy",
		Description: "Aqua Trivy SBOM generator (CycloneDX) and matcher on its own SBOMs",
		Options:     []string{"skip_db_update", "offline_scan"},
		New: func(s Spec) (any, error) {
			skip, err := s.Options.Bool("skip_db_update", false)
			if err != nil {
				return nil, err
			}
			offline, err := s.Options.Bool("offline_scan", false)
			if err != nil {
				return nil, err
			}
			return &Trivy{Bin: s.Bin, Runner: s.Runner, SkipDBUpdate: skip, OfflineScan: offline}, nil
		},
	})
}
