// Package export hands monitoring results to portfolio tools such as OWASP Dependency-Track
// and DefectDojo (docs/adr/0027-exporters.md). Exporters are plugins, selected by
// configuration; they receive what ShieldMon knows and change nothing in it.
package export

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nocs90/shieldmon/internal/notify"
	"github.com/nocs90/shieldmon/internal/redact"
	"github.com/nocs90/shieldmon/internal/report"
)

// Target is one monitored image as it is exported.
type Target struct {
	Ref        string // normalized reference, e.g. registry.example.com/payments/api:1.4
	Platform   string
	Digest     string
	Repository string // the reference without tag
	Tag        string // the tag, or the digest for a digest reference
	// MultiPlatform is true when the reference is monitored on several platforms.
	MultiPlatform bool
	// SBOM is the stored CycloneDX JSON SBOM of the digest (syft's), nil when there is none.
	SBOM []byte
	// Findings are the digest's open and risk-accepted findings as of the batch.
	Findings []report.Row
}

// Batch is what one export sends.
type Batch struct {
	Targets []Target
	Now     time.Time
	// Tool names the producer, e.g. "shieldmon 1.2.3".
	Tool string
}

// Exporter sends a batch to a tool. It reports per target what failed; an error is a failure
// of the whole export (configuration, cancellation).
type Exporter interface {
	Export(ctx context.Context, b Batch) (Result, error)
}

// Payloader is implemented by exporters that can show what they would send (--dry-run):
// one named document per target.
type Payloader interface {
	Payloads(b Batch) (map[string][]byte, error)
}

// Result is the outcome of an export.
type Result struct {
	Sent int
	// Failed maps target references to what went wrong, redacted.
	Failed map[string]string
}

// Spec is what a plugin is built from.
type Spec struct {
	// Name is the configured export's name.
	Name    string
	Options notify.Options
	// Env reads environment variables; os.Getenv unless a test replaces it.
	Env func(string) string
	// Transport carries HTTP requests; http.DefaultTransport unless a test replaces it.
	Transport http.RoundTripper
}

// notifySpec gives the notifiers' helpers (options, secrets, HTTP client) to an exporter.
func (s Spec) notifySpec() notify.Spec {
	return notify.Spec{Channel: s.Name, Options: s.Options, Env: s.Env, Transport: s.Transport}
}

// Secret reads the credential an option names (an environment variable).
func (s Spec) Secret(key string) (string, error) { return s.notifySpec().Secret(key) }

// HTTPClient is the hardened client of notifiers: no redirects, timeouts.
func (s Spec) HTTPClient() *http.Client { return notify.HTTPClient(s.notifySpec()) }

// Plugin describes an exporter.
type Plugin struct {
	Name        string
	Description string
	// Options are the option keys the exporter accepts; credentials end in "_env".
	Options []string
	New     func(Spec) (Exporter, error)
}

var (
	pluginsMu sync.RWMutex
	plugins   = map[string]Plugin{}
)

// Register adds an exporter plugin; it panics on a duplicate name (a programming error).
func Register(p Plugin) {
	pluginsMu.Lock()
	defer pluginsMu.Unlock()
	if _, dup := plugins[p.Name]; dup {
		panic("export: duplicate exporter " + p.Name)
	}
	plugins[p.Name] = p
}

// Lookup returns a registered exporter.
func Lookup(name string) (Plugin, bool) {
	pluginsMu.RLock()
	defer pluginsMu.RUnlock()
	p, ok := plugins[name]
	return p, ok
}

// Plugins returns every registered exporter, sorted by name.
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

// Config is one configured export.
type Config struct {
	Name     string
	Exporter string
	Options  map[string]any
}

// Instance is a configured, constructed export.
type Instance struct {
	Name     string
	Exporter string
	Sender   Exporter
}

var exportName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// New validates the configured exports and builds them, each with base (environment,
// transport: zero in production) completed by its name and options.
func New(cfgs []Config, base Spec) ([]Instance, error) {
	var out []Instance
	seen := map[string]bool{}
	for i, c := range cfgs {
		where := fmt.Sprintf("exports[%d]", i)
		if !exportName.MatchString(c.Name) {
			return nil, fmt.Errorf("%s: name %q: want lowercase letters, digits, - and _ (at most 64)", where, c.Name)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("%s: duplicate export name %q", where, c.Name)
		}
		seen[c.Name] = true
		p, ok := Lookup(c.Exporter)
		if !ok {
			var names []string
			for _, p := range Plugins() {
				names = append(names, p.Name)
			}
			return nil, fmt.Errorf("%s: unknown exporter %q (registered: %s)", where, c.Exporter, strings.Join(names, ", "))
		}
		for k, v := range c.Options {
			if !slices.Contains(p.Options, k) {
				return nil, fmt.Errorf("%s.options: unknown option %q (known: %s)", where, k, strings.Join(p.Options, ", "))
			}
			if s, ok := v.(string); ok && redact.String(s) != s {
				return nil, fmt.Errorf("%s.options: option %s looks like a credential: put it in an environment variable and name that variable instead", where, k)
			}
		}
		spec := base
		spec.Name, spec.Options = c.Name, c.Options
		e, err := p.New(spec)
		if err != nil {
			return nil, fmt.Errorf("%s: exporter %s: %s", where, c.Exporter, redact.Error(err))
		}
		out = append(out, Instance{Name: c.Name, Exporter: c.Exporter, Sender: e})
	}
	return out, nil
}

// fileName makes a payload file name of a reference: letters, digits, '.', '-' and '_'.
func fileName(s string) string {
	out := []byte(cut(s, 200))
	for i, c := range out {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-', c == '_':
		default:
			out[i] = '_'
		}
	}
	return string(out)
}

// cut bounds a string to n bytes on a rune boundary: the tools refuse longer fields.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
