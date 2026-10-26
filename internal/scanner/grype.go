package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/model"
)

// Grype matches syft SBOMs against the Anchore vulnerability DB.
type Grype struct {
	Bin    Binary
	Runner Runner
	// DBAutoUpdate lets UpdateDB refresh the DB (default true). Disable in air-gapped
	// setups that manage the DB out of band. grype itself never updates while matching.
	DBAutoUpdate bool
}

func (g *Grype) Name() string      { return "grype" }
func (g *Grype) Generator() string { return "syft" }

func (g *Grype) runner() Runner {
	r := g.Runner
	r.ExtraEnv = append(r.ExtraEnv, "GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_AUTO_UPDATE=false")
	if r.CacheDir != "" {
		r.ExtraEnv = append(r.ExtraEnv, "GRYPE_DB_CACHE_DIR="+filepath.Join(r.CacheDir, "grype", "db"))
	}
	return r
}

func (g *Grype) Match(ctx context.Context, sbomPath string) (Result, error) {
	bin, err := g.Bin.Resolve()
	if err != nil {
		return Result{}, err
	}
	abs, err := filepath.Abs(sbomPath)
	if err != nil {
		return Result{}, err
	}
	// Not --quiet: it also silences grype's errors.
	out, err := g.runner().Run(ctx, bin, "sbom:"+abs, "-o", "json")
	if err != nil {
		return Result{}, fmt.Errorf("grype: %w", err)
	}
	return ParseGrype(out)
}

// UpdateDB runs `grype db update`, which downloads only when the listing has a newer DB.
func (g *Grype) UpdateDB(ctx context.Context) error {
	if !g.DBAutoUpdate {
		return nil
	}
	bin, err := g.Bin.Resolve()
	if err != nil {
		return err
	}
	if _, err := g.runner().Run(ctx, bin, "db", "update"); err != nil {
		return fmt.Errorf("grype db update: %w", err)
	}
	return nil
}

type grypeCVSS struct {
	Version string `json:"version"`
	Vector  string `json:"vector"`
	Metrics struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"metrics"`
}

type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID          string      `json:"id"`
			Namespace   string      `json:"namespace"`
			Severity    string      `json:"severity"`
			DataSource  string      `json:"dataSource"`
			Description string      `json:"description"`
			CVSS        []grypeCVSS `json:"cvss"`
			EPSS        []struct {
				EPSS float64 `json:"epss"`
			} `json:"epss"`
			KnownExploited []struct {
				CVE string `json:"cve"`
			} `json:"knownExploited"`
			Fix struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID   string      `json:"id"`
			CVSS []grypeCVSS `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
			PURL    string `json:"purl"`
		} `json:"artifact"`
	} `json:"matches"`
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		DB      struct {
			Status struct {
				SchemaVersion string `json:"schemaVersion"`
				Built         string `json:"built"`
				Valid         bool   `json:"valid"`
			} `json:"status"`
		} `json:"db"`
	} `json:"descriptor"`
}

// ParseGrype parses `grype -o json` output.
func ParseGrype(data []byte) (Result, error) {
	var doc grypeDoc
	if err := decodeLimited(data, &doc); err != nil {
		return Result{}, err
	}
	tool := model.Tool{Name: "grype", Version: doc.Descriptor.Version, DBVersion: doc.Descriptor.DB.Status.SchemaVersion}
	if t, err := time.Parse(time.RFC3339, doc.Descriptor.DB.Status.Built); err == nil {
		tool.DBBuilt = t.UTC()
	}
	res := Result{Tool: tool}
	for _, m := range doc.Matches {
		v := m.Vulnerability
		rm := model.RawMatch{
			Scanner:     "grype",
			VulnID:      v.ID,
			PURL:        m.Artifact.PURL,
			PkgName:     m.Artifact.Name,
			PkgVersion:  m.Artifact.Version,
			PkgType:     m.Artifact.Type,
			Severity:    model.ParseSeverity(v.Severity),
			FixVersions: v.Fix.Versions,
			FixState:    v.Fix.State,
			DataSource:  v.DataSource,
			Title:       firstLine(v.Description, 200),
			KEV:         len(v.KnownExploited) > 0,
		}
		for _, e := range v.EPSS {
			rm.EPSS = max(rm.EPSS, e.EPSS)
		}
		cvss := v.CVSS
		for _, r := range m.RelatedVulnerabilities {
			if r.ID != "" && r.ID != v.ID {
				rm.Aliases = append(rm.Aliases, r.ID)
			}
			if len(v.CVSS) == 0 {
				cvss = append(cvss, r.CVSS...)
			}
		}
		rm.CVSSScore, rm.CVSSVector = bestCVSS(cvss)
		res.Matches = append(res.Matches, rm)
	}
	return res, nil
}

// bestCVSS returns the highest base score, preferring the newest CVSS major
// version present (v4 > v3 > v2).
func bestCVSS(list []grypeCVSS) (float64, string) {
	var score float64
	var vector string
	bestMajor := ""
	for _, c := range list {
		major, _, _ := strings.Cut(c.Version, ".")
		switch {
		case major > bestMajor:
			bestMajor, score, vector = major, c.Metrics.BaseScore, c.Vector
		case major == bestMajor && c.Metrics.BaseScore > score:
			score, vector = c.Metrics.BaseScore, c.Vector
		}
	}
	return score, vector
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// Tool reports grype's version and the status of its local vulnerability DB.
func (g *Grype) Tool(ctx context.Context) (model.Tool, error) {
	bin, err := g.Bin.Resolve()
	if err != nil {
		return model.Tool{}, err
	}
	r := g.runner()
	out, err := r.Run(ctx, bin, "version", "-o", "json")
	if err != nil {
		return model.Tool{}, err
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := decodeLimited(out, &v); err != nil {
		return model.Tool{}, err
	}
	tool := model.Tool{Name: "grype", Version: v.Version}
	out, err = r.Run(ctx, bin, "db", "status", "-o", "json")
	if err != nil {
		return tool, fmt.Errorf("grype db status: %w", err)
	}
	var st struct {
		SchemaVersion string `json:"schemaVersion"`
		Built         string `json:"built"`
		Valid         bool   `json:"valid"`
		Error         string `json:"error"`
	}
	if err := decodeLimited(out, &st); err != nil {
		return tool, err
	}
	if !st.Valid {
		return tool, fmt.Errorf("grype DB is not valid: %s", st.Error)
	}
	tool.DBVersion = st.SchemaVersion
	if t, err := time.Parse(time.RFC3339, st.Built); err == nil {
		tool.DBBuilt = t.UTC()
	}
	return tool, nil
}
