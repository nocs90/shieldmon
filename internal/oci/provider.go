package oci

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/redact"
)

// Provider authenticates to the registries it owns and lists their repositories and tags
// (docs/adr/0013-registry-providers.md). As an authn.Keychain it answers only for registries
// it owns, with short-lived credentials, and returns authn.Anonymous for any other, so that
// the next provider is asked.
type Provider interface {
	authn.Keychain
	// Owns reports whether the provider is responsible for registry (a host[:port]).
	Owns(registry string) bool
	// Repositories lists at most limit repositories of registry whose path starts with
	// prefix ("" for all), as full repository names.
	Repositories(ctx context.Context, registry, prefix string, limit int) ([]string, error)
	// Tags lists at most limit tags of repo, newest first when the registry says when a tag
	// was pushed, otherwise by descending version.
	Tags(ctx context.Context, repo name.Repository, limit int) ([]Tag, error)
}

// Tag is one tag of a repository. Pushed is zero when the registry does not say.
type Tag struct {
	Name   string
	Pushed time.Time
}

// ErrListingUnsupported is returned by providers that cannot list repositories of a registry.
var ErrListingUnsupported = errors.New("the registry does not support listing repositories")

// ProviderPlugin describes a registry provider. Providers register themselves from an init
// function, like scanner plugins (ADR 0008).
type ProviderPlugin struct {
	// Name is the value of registries[].provider that selects the provider.
	Name        string
	Description string
	// Options lists the keys accepted under registries[].options.
	Options []string
	// Default orders the providers that apply without configuration, lowest first; 0 means
	// the provider applies only where registries: binds hosts to it.
	Default int
	// Fallback marks a provider that owns every registry: it lends credentials in its
	// Default order, but lists a registry only when no other provider owns it.
	Fallback bool
	New      func(ProviderSpec) (Provider, error)
}

// ProviderSpec is what a provider receives at construction time.
type ProviderSpec struct {
	// Hosts are the registries a configured rule binds to the provider (exact hosts or
	// "*.suffix"); empty for a built-in default, which decides by itself what it owns.
	Hosts   []string
	Options ProviderOptions
	// Env reads environment variables; os.Getenv unless a test replaces it.
	Env func(string) string
}

// ProviderOptions are provider settings from configuration. Values are plain settings, never
// credentials: a credential is passed by naming an environment variable (an option ending in
// "_env").
type ProviderOptions map[string]any

// String returns a string option or def when unset.
func (o ProviderOptions) String(key, def string) (string, error) {
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

// Secret returns the value of the environment variable named by option key, "" when the
// option or the variable is unset.
func (s ProviderSpec) Secret(key string) (string, error) {
	envName, err := s.Options.String(key, "")
	if err != nil || envName == "" {
		return "", err
	}
	return s.env()(envName), nil
}

func (s ProviderSpec) env() func(string) string {
	if s.Env != nil {
		return s.Env
	}
	return os.Getenv
}

// MatchHost reports whether registry matches one of patterns: an exact host[:port], or
// "*.suffix" for any host under suffix.
func MatchHost(patterns []string, registry string) bool {
	registry = strings.ToLower(registry)
	for _, p := range patterns {
		p = strings.ToLower(p)
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(registry, "."+suffix) {
				return true
			}
		} else if registry == p {
			return true
		}
	}
	return false
}

var (
	providersMu sync.RWMutex
	providers   = map[string]ProviderPlugin{}
)

// RegisterProvider makes a provider available. It panics on duplicate or invalid
// registrations, which are programming errors.
func RegisterProvider(p ProviderPlugin) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if p.Name == "" || p.Description == "" || p.New == nil {
		panic("oci: RegisterProvider requires Name, Description and New")
	}
	if _, dup := providers[p.Name]; dup {
		panic("oci: duplicate provider " + p.Name)
	}
	providers[p.Name] = p
}

// Providers returns all registered providers sorted by name.
func Providers() []ProviderPlugin {
	providersMu.RLock()
	defer providersMu.RUnlock()
	out := make([]ProviderPlugin, 0, len(providers))
	for _, p := range providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// LookupProvider returns a registered provider.
func LookupProvider(name string) (ProviderPlugin, bool) {
	providersMu.RLock()
	defer providersMu.RUnlock()
	p, ok := providers[name]
	return p, ok
}

// Rule binds registry hosts to a provider (one entry of registries: in the config).
type Rule struct {
	Hosts    []string
	Provider string
	Options  map[string]any
}

// Registries is the configured set of providers: rules first, in order, then the built-in
// defaults. It is the keychain for every registry operation and routes listing.
type Registries struct {
	chain    []Provider
	fallback []bool // fallback[i]: chain[i] owns every registry
}

// NewRegistries validates rules and builds their providers, followed by the defaults.
func NewRegistries(rules []Rule) (*Registries, error) {
	r := &Registries{}
	for i, rule := range rules {
		where := fmt.Sprintf("registries[%d]", i)
		p, ok := LookupProvider(rule.Provider)
		if !ok {
			return nil, fmt.Errorf("%s: unknown provider %q (registered: %s)", where, rule.Provider, providerNames())
		}
		if len(rule.Hosts) == 0 {
			return nil, fmt.Errorf("%s: hosts is required", where)
		}
		for _, h := range rule.Hosts {
			if err := validHostPattern(h); err != nil {
				return nil, fmt.Errorf("%s: hosts: %w", where, err)
			}
		}
		if err := validOptions(p, rule.Options); err != nil {
			return nil, fmt.Errorf("%s.options: %w", where, err)
		}
		inst, err := p.New(ProviderSpec{Hosts: rule.Hosts, Options: rule.Options})
		if err != nil {
			return nil, fmt.Errorf("%s: provider %s: %w", where, rule.Provider, err)
		}
		r.chain = append(r.chain, inst)
		r.fallback = append(r.fallback, false)
	}
	if err := r.addDefaults(); err != nil {
		return nil, err
	}
	return r, nil
}

// addDefaults builds the providers that apply without configuration, in their order.
func (r *Registries) addDefaults() error {
	var plugins []ProviderPlugin
	for _, p := range Providers() {
		if p.Default > 0 {
			plugins = append(plugins, p)
		}
	}
	sort.SliceStable(plugins, func(i, j int) bool { return plugins[i].Default < plugins[j].Default })
	for _, p := range plugins {
		inst, err := p.New(ProviderSpec{})
		if err != nil {
			return fmt.Errorf("provider %s: %w", p.Name, err)
		}
		r.chain = append(r.chain, inst)
		r.fallback = append(r.fallback, p.Fallback)
	}
	return nil
}

// Resolve implements authn.Keychain: the first provider with credentials for the resource
// wins; anonymous when none has any.
func (r *Registries) Resolve(res authn.Resource) (authn.Authenticator, error) {
	for _, p := range r.chain {
		if !p.Owns(res.RegistryStr()) {
			continue
		}
		auth, err := p.Resolve(res)
		if err != nil {
			if errors.Is(err, ErrAuth) {
				return nil, fmt.Errorf("%w: %s", ErrAuth, redact.Error(err))
			}
			return nil, fmt.Errorf("%s", redact.Error(err))
		}
		if auth != authn.Anonymous {
			return auth, nil
		}
	}
	return authn.Anonymous, nil
}

// For returns the provider that lists registry: the first that owns it, a fallback provider
// (which owns every registry) only when no other does.
func (r *Registries) For(registry string) (Provider, error) {
	var fallback Provider
	for i, p := range r.chain {
		if !p.Owns(registry) {
			continue
		}
		if !r.fallback[i] {
			return p, nil
		}
		if fallback == nil {
			fallback = p
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("no registry provider for %s", registry)
}

// validOptions rejects unknown keys and values that look like credentials.
func validOptions(p ProviderPlugin, opts map[string]any) error {
	for k, v := range opts {
		if !slices.Contains(p.Options, k) {
			return fmt.Errorf("unknown option %q (known: %s)", k, strings.Join(p.Options, ", "))
		}
		if s, ok := v.(string); ok && redact.String(s) != s {
			return fmt.Errorf("option %s looks like a credential: put it in an environment variable and name that variable instead", k)
		}
	}
	return nil
}

func validHostPattern(h string) error {
	host := strings.TrimPrefix(h, "*.")
	if host == "" || strings.ContainsAny(host, "/*@ ") {
		return fmt.Errorf("invalid host pattern %q (want host[:port] or *.suffix)", h)
	}
	if _, err := name.NewRegistry(host, name.StrictValidation); err != nil {
		return fmt.Errorf("invalid host pattern %q: %w", h, err)
	}
	return nil
}

func providerNames() string {
	var out []string
	for _, p := range Providers() {
		out = append(out, p.Name)
	}
	return strings.Join(out, ", ")
}
