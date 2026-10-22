// Package scanner wraps external SBOM generators and vulnerability matchers
// behind small interfaces. Scanners never talk to registries: they receive a
// local OCI layout (generators) or a stored SBOM (matchers).
package scanner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nocs90/shieldmon/internal/model"
)

// SBOM formats.
const (
	FormatCycloneDXJSON = "cyclonedx-json"
	FormatSPDXJSON      = "spdx-json"
)

// SBOMFile is a generated SBOM document on disk.
type SBOMFile struct {
	Format string
	Path   string
}

// Source describes the image being cataloged, for SBOM metadata.
type Source struct {
	OCIDir  string // local OCI image layout containing exactly one image
	Name    string // repository, e.g. docker.io/library/alpine
	Version string // manifest digest
}

// Generator produces SBOMs from a local OCI layout.
type Generator interface {
	Name() string
	Tool(ctx context.Context) (model.Tool, error)
	// Generate writes one or more SBOM files into outDir. The first returned
	// file is the primary document consumed by matchers.
	Generate(ctx context.Context, src Source, outDir string) ([]SBOMFile, error)
}

// Matcher matches a stored SBOM against its vulnerability database.
type Matcher interface {
	Name() string
	// Generator names the SBOM generator whose output this matcher is
	// validated against. Cross-tool SBOM consumption loses data (e.g. trivy
	// on a syft CycloneDX misses distro source-package mapping).
	Generator() string
	Match(ctx context.Context, sbomPath string) (Result, error)
}

// Result is the output of one matcher run.
type Result struct {
	Tool    model.Tool
	Matches []model.RawMatch
}

// Set is the configured collection of generators and matchers.
type Set struct {
	Generators map[string]Generator
	Matchers   []Matcher
}

// RequiredGenerators returns the generators needed by the enabled matchers.
func (s Set) RequiredGenerators() ([]Generator, error) {
	seen := map[string]bool{}
	var out []Generator
	for _, m := range s.Matchers {
		g, ok := s.Generators[m.Generator()]
		if !ok {
			return nil, fmt.Errorf("matcher %s requires generator %s, which is not configured", m.Name(), m.Generator())
		}
		if !seen[g.Name()] {
			seen[g.Name()] = true
			out = append(out, g)
		}
	}
	return out, nil
}

// decodeLimited unmarshals JSON scanner output. Output size is already
// bounded by Runner; this is a single place to harden decoding later.
func decodeLimited(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("decode scanner output: %w", err)
	}
	return nil
}
