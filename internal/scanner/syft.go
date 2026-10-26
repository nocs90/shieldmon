package scanner

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/nocs90/shieldmon/internal/model"
)

// Syft generates CycloneDX and SPDX SBOMs. Its CycloneDX output feeds grype.
type Syft struct {
	Bin    Binary
	Runner Runner
}

func (s *Syft) Name() string { return "syft" }

func (s *Syft) runner() Runner {
	r := s.Runner
	r.ExtraEnv = append(r.ExtraEnv, "SYFT_CHECK_FOR_APP_UPDATE=false")
	return r
}

func (s *Syft) Tool(ctx context.Context) (model.Tool, error) {
	bin, err := s.Bin.Resolve()
	if err != nil {
		return model.Tool{}, err
	}
	out, err := s.runner().Run(ctx, bin, "version", "-o", "json")
	if err != nil {
		return model.Tool{}, err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := decodeLimited(out, &v); err != nil {
		return model.Tool{}, err
	}
	return model.Tool{Name: "syft", Version: v.Version}, nil
}

func (s *Syft) Generate(ctx context.Context, src Source, outDir string) ([]SBOMFile, error) {
	bin, err := s.Bin.Resolve()
	if err != nil {
		return nil, err
	}
	cdx := filepath.Join(outDir, "syft.cdx.json")
	spdx := filepath.Join(outDir, "syft.spdx.json")
	args := []string{
		// Not --quiet: it also silences syft's errors, which the Runner reports (bounded,
		// redacted) and classifies (a refused write, for instance).
		"scan", "oci-dir:" + src.OCIDir,
		"--source-name", src.Name,
		"--source-version", src.Version,
		"-o", FormatCycloneDXJSON + "=" + cdx,
		"-o", FormatSPDXJSON + "=" + spdx,
	}
	if _, err := s.runner().Run(ctx, bin, args...); err != nil {
		return nil, fmt.Errorf("syft: %w", err)
	}
	return []SBOMFile{{Format: FormatCycloneDXJSON, Path: cdx}, {Format: FormatSPDXJSON, Path: spdx}}, nil
}
