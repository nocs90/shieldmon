package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// trivyCommonFlags disable telemetry and version-check calls home. The scan cache stays
// in memory: results derived from hostile layers are never persisted for later scans,
// and the cache directory can be read-only.
var trivyCommonFlags = []string{"--quiet", "--disable-telemetry", "--skip-version-check", "--cache-backend", "memory"}

// Trivy acts both as an SBOM generator (CycloneDX) and as a matcher for its
// own SBOMs.
type Trivy struct {
	Bin    Binary
	Runner Runner
	// SkipDBUpdate prevents trivy from downloading its DB during matching.
	SkipDBUpdate bool
	// OfflineScan stops trivy from querying external APIs (e.g. Maven Central)
	// while cataloging; improves privacy at the cost of Java coverage.
	OfflineScan bool
}

func (t *Trivy) Name() string      { return "trivy" }
func (t *Trivy) Generator() string { return "trivy" }

// runner points trivy at the cache directory explicitly: on macOS it ignores
// XDG_CACHE_HOME.
func (t *Trivy) runner() Runner {
	r := t.Runner
	if r.CacheDir != "" {
		r.ExtraEnv = append(r.ExtraEnv, "TRIVY_CACHE_DIR="+filepath.Join(r.CacheDir, "trivy"))
	}
	return r
}

func (t *Trivy) Tool(ctx context.Context) (model.Tool, error) {
	bin, err := t.Bin.Resolve()
	if err != nil {
		return model.Tool{}, err
	}
	out, err := t.runner().Run(ctx, bin, "version", "--format", "json")
	if err != nil {
		return model.Tool{}, err
	}
	return parseTrivyVersion(out)
}

func parseTrivyVersion(out []byte) (model.Tool, error) {
	var v struct {
		Version         string `json:"Version"`
		VulnerabilityDB *struct {
			Version   int    `json:"Version"`
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if err := decodeLimited(out, &v); err != nil {
		return model.Tool{}, err
	}
	tool := model.Tool{Name: "trivy", Version: v.Version}
	if v.VulnerabilityDB != nil {
		tool.DBVersion = fmt.Sprintf("v%d", v.VulnerabilityDB.Version)
		if ts, err := time.Parse(time.RFC3339Nano, v.VulnerabilityDB.UpdatedAt); err == nil {
			tool.DBBuilt = ts.UTC()
		}
	}
	return tool, nil
}

func (t *Trivy) Generate(ctx context.Context, src Source, outDir string) ([]SBOMFile, error) {
	bin, err := t.Bin.Resolve()
	if err != nil {
		return nil, err
	}
	out := filepath.Join(outDir, "trivy.cdx.json")
	args := append([]string{"image", "--input", src.OCIDir, "--format", "cyclonedx", "--output", out}, trivyCommonFlags...)
	if t.OfflineScan {
		args = append(args, "--offline-scan")
	}
	if _, err := t.runner().Run(ctx, bin, args...); err != nil {
		return nil, fmt.Errorf("trivy: %w", err)
	}
	return []SBOMFile{{Format: FormatCycloneDXJSON, Path: out}}, nil
}

func (t *Trivy) Match(ctx context.Context, sbomPath string) (Result, error) {
	bin, err := t.Bin.Resolve()
	if err != nil {
		return Result{}, err
	}
	args := append([]string{"sbom", "--format", "json", "--scanners", "vuln"}, trivyCommonFlags...)
	if t.SkipDBUpdate {
		args = append(args, "--skip-db-update")
	}
	args = append(args, "--", sbomPath)
	out, err := t.runner().Run(ctx, bin, args...)
	if err != nil {
		return Result{}, fmt.Errorf("trivy: %w", err)
	}
	res, err := ParseTrivy(out)
	if err != nil {
		return Result{}, err
	}
	// The scan report does not include DB metadata; ask trivy separately.
	if tool, err := t.Tool(ctx); err == nil {
		res.Tool = tool
	}
	return res, nil
}

type trivyDoc struct {
	Results []struct {
		Target          string `json:"Target"`
		Vulnerabilities []struct {
			VulnerabilityID string   `json:"VulnerabilityID"`
			VendorIDs       []string `json:"VendorIDs"`
			PkgName         string   `json:"PkgName"`
			PkgIdentifier   struct {
				PURL string `json:"PURL"`
			} `json:"PkgIdentifier"`
			InstalledVersion string `json:"InstalledVersion"`
			FixedVersion     string `json:"FixedVersion"`
			Status           string `json:"Status"`
			Severity         string `json:"Severity"`
			Title            string `json:"Title"`
			DataSource       *struct {
				ID string `json:"ID"`
			} `json:"DataSource"`
			CVSS map[string]struct {
				V3Vector  string  `json:"V3Vector"`
				V3Score   float64 `json:"V3Score"`
				V40Vector string  `json:"V40Vector"`
				V40Score  float64 `json:"V40Score"`
			} `json:"CVSS"`
		} `json:"Vulnerabilities"`
	} `json:"Results"`
}

// ParseTrivy parses `trivy ... --format json` output. Tool metadata is not
// part of the report and must be filled by the caller.
func ParseTrivy(data []byte) (Result, error) {
	var doc trivyDoc
	if err := decodeLimited(data, &doc); err != nil {
		return Result{}, err
	}
	res := Result{Tool: model.Tool{Name: "trivy"}}
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			rm := model.RawMatch{
				Scanner:    "trivy",
				VulnID:     v.VulnerabilityID,
				Aliases:    v.VendorIDs,
				PURL:       v.PkgIdentifier.PURL,
				PkgName:    v.PkgName,
				PkgVersion: v.InstalledVersion,
				Severity:   model.ParseSeverity(v.Severity),
				FixState:   v.Status,
				Title:      v.Title,
			}
			if v.DataSource != nil {
				rm.DataSource = v.DataSource.ID
			}
			for _, f := range strings.Split(v.FixedVersion, ",") {
				if f = strings.TrimSpace(f); f != "" {
					rm.FixVersions = append(rm.FixVersions, f)
				}
			}
			// Prefer NVD's score for consistency with grype; otherwise take the max.
			if c, ok := v.CVSS["nvd"]; ok && (c.V40Score > 0 || c.V3Score > 0) {
				rm.CVSSScore, rm.CVSSVector = c.V3Score, c.V3Vector
				if c.V40Score > 0 {
					rm.CVSSScore, rm.CVSSVector = c.V40Score, c.V40Vector
				}
			} else {
				for _, c := range v.CVSS {
					if c.V3Score > rm.CVSSScore {
						rm.CVSSScore, rm.CVSSVector = c.V3Score, c.V3Vector
					}
				}
			}
			res.Matches = append(res.Matches, rm)
		}
	}
	return res, nil
}
