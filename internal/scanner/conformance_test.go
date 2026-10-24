package scanner_test

import (
	"testing"

	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/scanner/scannertest"
)

func TestBuiltinPluginsConform(t *testing.T) {
	for _, name := range []string{"syft", "grype", "trivy"} {
		t.Run(name, func(t *testing.T) { scannertest.CheckPlugin(t, name) })
	}
}

// TestSandboxBackendsConform probes every backend that confines scanners ("none" is the
// explicit opt-out). Backends that cannot run on this host are skipped, except the one
// named by SHIELDMON_TEST_SANDBOX.
func TestSandboxBackendsConform(t *testing.T) {
	for _, b := range scanner.SandboxBackends() {
		if !scanner.Confined(b.New()) {
			continue
		}
		t.Run(b.Name, func(t *testing.T) { scannertest.CheckSandbox(t, b.Name) })
	}
}

func TestBuiltinParsersConform(t *testing.T) {
	t.Run("grype", func(t *testing.T) {
		scannertest.CheckParser(t, "grype", scanner.ParseGrype, "testdata/grype-alpine-3.18.0.json")
	})
	t.Run("trivy", func(t *testing.T) {
		scannertest.CheckParser(t, "trivy", scanner.ParseTrivy, "testdata/trivy-alpine-3.18.0.json")
	})
}

func TestBuildRejectsMisconfiguration(t *testing.T) {
	if _, err := scanner.Build([]string{"nope"}, nil, scanner.Runner{}); err == nil {
		t.Error("unknown plugin must fail")
	}
	if _, err := scanner.Build([]string{"syft"}, nil, scanner.Runner{}); err == nil {
		t.Error("a generator-only plugin cannot be a matcher")
	}
	specs := map[string]scanner.Spec{"grype": {Options: scanner.Options{"db_auto_updte": true}}}
	if _, err := scanner.Build([]string{"grype"}, specs, scanner.Runner{}); err == nil {
		t.Error("misspelled option must fail")
	}
	specs = map[string]scanner.Spec{"grype": {Options: scanner.Options{"db_auto_update": "yes"}}}
	if _, err := scanner.Build([]string{"grype"}, specs, scanner.Runner{}); err == nil {
		t.Error("wrongly typed option must fail")
	}
	set, err := scanner.Build([]string{"grype", "trivy"}, nil, scanner.Runner{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Matchers) != 2 || len(set.Generators) != 2 {
		t.Fatalf("set = %+v", set)
	}
	// trivy is generator and matcher: one shared instance.
	if set.Generators["trivy"] != set.Matchers[1].(scanner.Generator) {
		t.Error("trivy must be a single instance serving both roles")
	}
}
