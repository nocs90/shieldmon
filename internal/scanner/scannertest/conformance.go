// Package scannertest is the conformance kit every scanner adapter must
// pass. Contributors call these helpers from their adapter's tests; CI runs
// them for all built-in adapters. See docs/extending/conformance.md.
package scannertest

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/scanner"
)

// ParseFunc is an adapter's pure output parser (e.g. scanner.ParseGrype).
type ParseFunc func([]byte) (scanner.Result, error)

// hostileInputs are malformed or adversarial scanner outputs. A parser must
// return an error or an empty result for each, and must never panic.
var hostileInputs = map[string][]byte{
	"empty":            {},
	"null":             []byte("null"),
	"not json":         []byte("<html>502 Bad Gateway</html>"),
	"truncated":        []byte(`{"matches":[{"vulnerability":{"id":"CVE-2024-1`),
	"wrong types":      []byte(`{"matches":"yes","Results":42}`),
	"deep nesting":     []byte(strings.Repeat("[", 10000) + strings.Repeat("]", 10000)),
	"ansi and control": []byte("\x1b[31mERROR\x1b[0m\x00\x01"),
}

// CheckPlugin verifies a plugin's registration metadata and construction.
func CheckPlugin(t *testing.T, name string) {
	t.Helper()
	p, ok := scanner.Lookup(name)
	if !ok {
		t.Fatalf("plugin %q is not registered", name)
	}
	if p.Description == "" {
		t.Errorf("plugin %q has no description", name)
	}
	inst, err := p.New(scanner.Spec{Bin: scanner.Binary{Name: name}})
	if err != nil {
		t.Fatalf("plugin %q fails to construct with defaults: %v", name, err)
	}
	g, isGen := inst.(scanner.Generator)
	m, isMatch := inst.(scanner.Matcher)
	if !isGen && !isMatch {
		t.Fatalf("plugin %q is neither a Generator nor a Matcher", name)
	}
	if isGen && g.Name() != name {
		t.Errorf("generator Name() = %q, want %q", g.Name(), name)
	}
	if isMatch {
		if m.Name() != name {
			t.Errorf("matcher Name() = %q, want %q", m.Name(), name)
		}
		gp, ok := scanner.Lookup(m.Generator())
		if !ok {
			t.Fatalf("matcher %q requires unregistered generator %q", name, m.Generator())
		}
		gi, err := gp.New(scanner.Spec{Bin: scanner.Binary{Name: gp.Name}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := gi.(scanner.Generator); !ok {
			t.Errorf("matcher %q names %q as generator, but it does not implement Generator", name, m.Generator())
		}
	}
	if _, err := p.New(scanner.Spec{Options: scanner.Options{"__bogus__": 1}}); err == nil {
		// Unknown keys are rejected by Build; plugins may still accept them in
		// New, so this is informational only.
		t.Logf("plugin %q accepts unknown options in New (Build still rejects them)", name)
	}
}

// CheckParser verifies a parser against real fixture output and hostile input.
// Fixtures must be trimmed real scanner output (testdata/<tool>-*.json).
func CheckParser(t *testing.T, scannerName string, parse ParseFunc, fixtures ...string) {
	t.Helper()
	if len(fixtures) == 0 {
		t.Fatal("at least one real-output fixture is required")
	}
	for _, path := range fixtures {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		res, err := parse(data)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if len(res.Matches) == 0 {
			t.Errorf("%s: no matches parsed from a real fixture", path)
		}
		for i, m := range res.Matches {
			if m.Scanner != scannerName {
				t.Errorf("%s match %d: Scanner = %q, want %q", path, i, m.Scanner, scannerName)
			}
			if m.VulnID == "" {
				t.Errorf("%s match %d: empty VulnID", path, i)
			}
			if m.PURL == "" && (m.PkgName == "" || m.PkgVersion == "") {
				t.Errorf("%s match %d: neither PURL nor name+version", path, i)
			}
			if m.Severity < model.SeverityUnknown || m.Severity > model.SeverityCritical {
				t.Errorf("%s match %d: severity out of range", path, i)
			}
		}
		// Output must normalize without losing matches entirely.
		if merged := normalize.Merge(res.Matches); len(merged) == 0 {
			t.Errorf("%s: normalization dropped every match", path)
		}
	}
	for name, in := range hostileInputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("hostile input %q: parser panicked: %v", name, r)
				}
			}()
			res, err := parse(in)
			if err == nil && len(res.Matches) > 0 {
				t.Errorf("hostile input %q produced %d matches", name, len(res.Matches))
			}
		}()
	}
}

// CheckMatcher runs a real matcher on an SBOM produced by its generator.
// Use from integration tests only (needs the binary and a vulnerability DB).
func CheckMatcher(t *testing.T, m scanner.Matcher, sbomPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := m.Match(ctx, sbomPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Tool.Name != m.Name() || res.Tool.Version == "" {
		t.Errorf("tool metadata incomplete: %+v", res.Tool)
	}
	if res.Tool.DBBuilt.IsZero() {
		t.Error("matcher must report its vulnerability DB build time (needed for db_stale health checks)")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := m.Match(cancelled, sbomPath); err == nil {
		t.Error("matcher must honour context cancellation")
	}
}
