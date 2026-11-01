package scanner

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/redact"
)

// OSV matches syft SBOMs against the OSV.dev databases with osv-scanner, offline: the
// databases are downloaded per ecosystem by UpdateDB, and Match never reaches the network
// (osv-scanner's online mode would send the package list to api.osv.dev).
//
// osv-scanner goes on when a database cannot be loaded and still exits 1 when it found
// vulnerabilities elsewhere, so a result is trusted only when ShieldMon chose what was
// scanned and osv-scanner reported no error (docs/adr/0028-osv-scanner-matcher.md).
type OSV struct {
	Bin    Binary
	Runner Runner
	// DBAutoUpdate lets UpdateDB refresh the databases (default true). Disable in
	// air-gapped setups that place them under the cache directory out of band.
	DBAutoUpdate bool
	// Ecosystems are the OSV ecosystems matched and kept current. osv-scanner downloads
	// only the ecosystems of what it scans, and the scan has no network.
	Ecosystems []string
}

// osvProbeName cannot be registered in any package registry (it has a space): a probe
// package nobody can publish never matches an advisory.
const osvProbeName = "shieldmon db-probe"

// OSVEcosystems are the ecosystems the adapter supports, each with the package URL of a
// probe package that makes osv-scanner download its database.
var OSVEcosystems = map[string]string{
	"Alpine":     "pkg:apk/alpine/shieldmon%20db-probe@0.0.0-r0?distro=alpine-3.20",
	"Chainguard": "pkg:apk/chainguard/shieldmon%20db-probe@0.0.0-r0",
	"Wolfi":      "pkg:apk/wolfi/shieldmon%20db-probe@0.0.0-r0",
	"Debian":     "pkg:deb/debian/shieldmon%20db-probe@0.0.0?distro=debian-12",
	"Ubuntu":     "pkg:deb/ubuntu/shieldmon%20db-probe@0.0.0?distro=ubuntu-24.04",
	"npm":        "pkg:npm/shieldmon%20db-probe@0.0.0",
	"PyPI":       "pkg:pypi/shieldmon%20db-probe@0.0.0",
	"Go":         "pkg:golang/example.invalid/shieldmon%20db-probe@v0.0.0",
	"Maven":      "pkg:maven/invalid.shieldmon/db%20probe@0.0.0",
	"crates.io":  "pkg:cargo/shieldmon%20db-probe@0.0.0",
	"RubyGems":   "pkg:gem/shieldmon%20db-probe@0.0.0",
	"NuGet":      "pkg:nuget/shieldmon%20db-probe@0.0.0",
	"Packagist":  "pkg:composer/shieldmon/db%20probe@0.0.0",
	"Hex":        "pkg:hex/shieldmon%20db-probe@0.0.0",
	"Pub":        "pkg:pub/shieldmon%20db-probe@0.0.0",
}

// osvPURLTypes maps package URL types to the OSV ecosystem osv-scanner matches them in
// (osv-scalibr's purl/ecosystem and extractor/convert). Components of other types (rpm,
// generic, binary, …) are left out of the scan: grype and trivy cover them.
var osvPURLTypes = map[string]string{
	"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io",
	"gem": "RubyGems", "nuget": "NuGet", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
}

// osvEcosystem is the OSV ecosystem of a package URL, "" when the adapter does not match it.
func osvEcosystem(purl string) string {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	ns := strings.ToLower(p.Namespace)
	switch p.Type {
	case "apk":
		return map[string]string{"alpine": "Alpine", "wolfi": "Wolfi", "chainguard": "Chainguard"}[ns]
	case "deb":
		return map[string]string{"debian": "Debian", "ubuntu": "Ubuntu"}[ns]
	}
	return osvPURLTypes[p.Type]
}

// DefaultOSVEcosystems is every ecosystem the adapter supports.
func DefaultOSVEcosystems() []string {
	out := make([]string, 0, len(OSVEcosystems))
	for e := range OSVEcosystems {
		out = append(out, e)
	}
	slices.Sort(out)
	return out
}

func (o *OSV) Name() string      { return "osv-scanner" }
func (o *OSV) Generator() string { return "syft" }

// osvFlags keep every scan offline (--offline also disables transitive resolution and any
// plugin that calls a remote service) and limit stderr to errors.
var osvFlags = []string{"--offline", "--verbosity", "error", "--format", "json"}

// osvMaxSBOMBytes bounds the SBOM read into memory, as the engine bounds stored SBOMs.
const osvMaxSBOMBytes = 256 << 20

// dbRoot is osv-scanner's local database path. It keeps each ecosystem's database at
// <root>/osv-scalibr/<ecosystem>/all.zip.
func (o *OSV) dbRoot() (string, error) {
	if o.Runner.CacheDir == "" {
		return "", errors.New("osv-scanner: needs a cache directory for its offline databases")
	}
	return filepath.Join(o.Runner.CacheDir, "osv-scanner"), nil
}

// safeEcosystem bounds the ecosystem names that become paths: some come from scanner output
// ("crates.io", "Rocky Linux", "Alpine:v3.18" before the version is cut).
var safeEcosystem = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

func (o *OSV) dbFile(root, ecosystem string) (string, error) {
	if !safeEcosystem.MatchString(ecosystem) || strings.Contains(ecosystem, "..") {
		return "", fmt.Errorf("osv-scanner: unexpected ecosystem name %q", truncateRunes(ecosystem, 64))
	}
	return filepath.Join(root, "osv-scalibr", ecosystem, "all.zip"), nil
}

// runner sets osv-scanner's database path. With found, exit status 1 (vulnerabilities
// found) is success; every other non-zero status is a failure.
func (o *OSV) runner(root string, found bool) Runner {
	r := o.Runner
	r.ExtraEnv = append(slices.Clip(r.ExtraEnv), "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="+root)
	if found {
		r.OKExitCodes = append(slices.Clip(r.OKExitCodes), 1)
	}
	return r
}

// run runs a scan and fails when osv-scanner logged an error, whatever its exit status:
// with --verbosity error, stderr holds errors only.
func (o *OSV) run(ctx context.Context, r Runner, bin string, args ...string) ([]byte, error) {
	out, stderr, err := r.RunWithStderr(ctx, bin, args...)
	if err != nil {
		return nil, fmt.Errorf("osv-scanner: %w", err)
	}
	if msg := strings.TrimSpace(string(stderr)); msg != "" {
		return nil, fmt.Errorf("osv-scanner reported errors: %s", truncateRunes(redact.String(msg), 2000))
	}
	return out, nil
}

// stage writes an SBOM to a private directory under the name osv-scanner requires
// (*.cdx.json): it picks its parser by file name, and reads -L up to the first ':' as a
// parser name. The directory is added to the policy's inputs.
func (o *OSV) stage(ctx context.Context, data []byte) (context.Context, string, func(), error) {
	base := o.Runner.TempDir
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, "", nil, err
	}
	dir, err := os.MkdirTemp(base, "osv-sbom-")
	if err != nil {
		return nil, "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	path := filepath.Join(dir, "sbom.cdx.json")
	if strings.Contains(path, ":") {
		cleanup()
		return nil, "", nil, fmt.Errorf("osv-scanner: cannot read a path containing ':' (%s)", dir)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		cleanup()
		return nil, "", nil, err
	}
	p := PolicyFrom(ctx)
	p.ReadOnly = append(slices.Clip(p.ReadOnly), dir)
	return WithPolicy(ctx, p), path, cleanup, nil
}

// selectComponents keeps the SBOM components osv-scanner is to match, by their package
// URL, and returns their ecosystems. A component of a supported ecosystem that is not
// configured is an error: leaving it out would hide what osv-scanner could find.
func (o *OSV) selectComponents(data []byte) ([]byte, []string, error) {
	var doc map[string]json.RawMessage
	if err := decodeLimited(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("osv-scanner: %w", err)
	}
	var comps []json.RawMessage
	if raw, ok := doc["components"]; ok {
		if err := decodeLimited(raw, &comps); err != nil {
			return nil, nil, fmt.Errorf("osv-scanner: SBOM components: %w", err)
		}
	}
	var keep []json.RawMessage
	var ecosystems, unconfigured []string
	for _, c := range comps {
		var head struct {
			PURL string `json:"purl"`
		}
		if err := json.Unmarshal(c, &head); err != nil {
			return nil, nil, fmt.Errorf("osv-scanner: SBOM component: %w", err)
		}
		e := osvEcosystem(head.PURL)
		switch {
		case e == "":
			continue
		case !slices.Contains(o.Ecosystems, e):
			if !slices.Contains(unconfigured, e) {
				unconfigured = append(unconfigured, e)
			}
			continue
		case !slices.Contains(ecosystems, e):
			ecosystems = append(ecosystems, e)
		}
		keep = append(keep, c)
	}
	if len(unconfigured) > 0 {
		slices.Sort(unconfigured)
		return nil, nil, fmt.Errorf("osv-scanner: the SBOM has %s packages: add the ecosystems to scanners.tools.osv-scanner.options.ecosystems", strings.Join(unconfigured, ", "))
	}
	slices.Sort(ecosystems)
	kept, err := json.Marshal(keep)
	if err != nil {
		return nil, nil, err
	}
	doc["components"] = kept
	// References between the components left are not needed to match them.
	delete(doc, "dependencies")
	out, err := json.Marshal(doc)
	return out, ecosystems, err
}

func (o *OSV) Match(ctx context.Context, sbomPath string) (Result, error) {
	bin, err := o.Bin.Resolve()
	if err != nil {
		return Result{}, err
	}
	root, err := o.dbRoot()
	if err != nil {
		return Result{}, err
	}
	st, err := os.Stat(sbomPath)
	if err != nil {
		return Result{}, err
	}
	if st.Size() > osvMaxSBOMBytes {
		return Result{}, fmt.Errorf("osv-scanner: SBOM of %d bytes exceeds %d", st.Size(), osvMaxSBOMBytes)
	}
	data, err := os.ReadFile(sbomPath)
	if err != nil {
		return Result{}, err
	}
	scan, ecosystems, err := o.selectComponents(data)
	if err != nil {
		return Result{}, err
	}
	tool, err := o.version(ctx, bin, root)
	if err != nil {
		return Result{}, err
	}
	if len(ecosystems) == 0 {
		// Nothing osv-scanner matches (an rpm-based image, say), and it fails on an SBOM
		// without packages: the configured databases date the empty result.
		tool.DBBuilt, _, err = o.dbTimes(root, o.Ecosystems)
		return Result{Tool: tool}, err
	}
	oldest, missing, err := o.dbTimes(root, ecosystems)
	if err != nil {
		return Result{}, err
	}
	if len(missing) > 0 {
		return Result{}, fmt.Errorf("osv-scanner: no offline database for %s: run the DB update", strings.Join(missing, ", "))
	}
	mctx, path, cleanup, err := o.stage(ctx, scan)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	args := append(append([]string{"scan", "source"}, osvFlags...), "-L", path)
	out, err := o.run(mctx, o.runner(root, true), bin, args...)
	if err != nil {
		return Result{}, err
	}
	res, seen, err := parseOSV(out)
	if err != nil {
		return Result{}, err
	}
	for _, e := range seen {
		if !slices.Contains(ecosystems, e) {
			return Result{}, fmt.Errorf("osv-scanner: matched packages in %q, which ShieldMon did not expect: its result cannot be checked for completeness", truncateRunes(e, 64))
		}
	}
	tool.DBBuilt = oldest
	res.Tool = tool
	return res, nil
}

// dbTimes returns the oldest modification time of the ecosystems' databases and the
// ecosystems that have none.
func (o *OSV) dbTimes(root string, ecosystems []string) (time.Time, []string, error) {
	var oldest time.Time
	var missing []string
	for _, e := range ecosystems {
		f, err := o.dbFile(root, e)
		if err != nil {
			return time.Time{}, nil, err
		}
		st, err := os.Stat(f)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			missing = append(missing, e)
		case err != nil:
			return time.Time{}, nil, err
		case oldest.IsZero() || st.ModTime().Before(oldest):
			oldest = st.ModTime().UTC()
		}
	}
	return oldest, missing, nil
}

// Tool reports osv-scanner's version and the age of the oldest configured database.
func (o *OSV) Tool(ctx context.Context) (model.Tool, error) {
	bin, err := o.Bin.Resolve()
	if err != nil {
		return model.Tool{}, err
	}
	root, err := o.dbRoot()
	if err != nil {
		return model.Tool{}, err
	}
	tool, err := o.version(ctx, bin, root)
	if err != nil {
		return tool, err
	}
	oldest, missing, err := o.dbTimes(root, o.Ecosystems)
	if err != nil {
		return tool, err
	}
	if len(missing) > 0 {
		return tool, fmt.Errorf("osv-scanner: no offline database for %s", strings.Join(missing, ", "))
	}
	tool.DBBuilt = oldest
	return tool, nil
}

func (o *OSV) version(ctx context.Context, bin, root string) (model.Tool, error) {
	out, err := o.runner(root, false).Run(ctx, bin, "--version")
	if err != nil {
		return model.Tool{}, fmt.Errorf("osv-scanner: %w", err)
	}
	tool := model.Tool{Name: "osv-scanner", Version: parseOSVVersion(out), DBVersion: "osv-offline"}
	if tool.Version == "" {
		return tool, errors.New("osv-scanner: no version in --version output")
	}
	return tool, nil
}

func parseOSVVersion(out []byte) string {
	for line := range strings.SplitSeq(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "osv-scanner version:"); ok {
			v = strings.TrimSpace(v)
			if len(v) <= 64 {
				return v
			}
		}
	}
	return ""
}

// UpdateDB downloads the configured ecosystems' databases by scanning a probe SBOM that
// ShieldMon writes, one placeholder package per ecosystem: the only process with network
// never sees an image's SBOM. Any non-zero status, logged error or match on a probe fails
// the update. osv-scanner downloads a database only when its checksum changed; each one is
// then marked verified now, the time its content was known current.
func (o *OSV) UpdateDB(ctx context.Context) error {
	if !o.DBAutoUpdate {
		return nil
	}
	bin, err := o.Bin.Resolve()
	if err != nil {
		return err
	}
	root, err := o.dbRoot()
	if err != nil {
		return err
	}
	probe, err := osvProbe(o.Ecosystems)
	if err != nil {
		return err
	}
	uctx, path, cleanup, err := o.stage(ctx, probe)
	if err != nil {
		return err
	}
	defer cleanup()
	args := []string{"scan", "source", "--offline", "--download-offline-databases", "--verbosity", "error", "--format", "json", "-L", path}
	out, err := o.run(uctx, o.runner(root, false), bin, args...)
	if err != nil {
		return fmt.Errorf("osv-scanner database download: %w", err)
	}
	res, err := ParseOSV(out)
	if err != nil {
		return fmt.Errorf("osv-scanner database download: %w", err)
	}
	if len(res.Matches) > 0 {
		return fmt.Errorf("osv-scanner database download: %d matches on the probe packages, which no registry can publish", len(res.Matches))
	}
	_, missing, err := o.dbTimes(root, o.Ecosystems)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("osv-scanner database download: nothing downloaded for %s", strings.Join(missing, ", "))
	}
	now := time.Now()
	for _, e := range o.Ecosystems {
		f, err := o.dbFile(root, e)
		if err != nil {
			return err
		}
		if err := os.Chtimes(f, now, now); err != nil {
			return err
		}
	}
	return nil
}

// osvProbe is a CycloneDX SBOM with one placeholder package per ecosystem.
func osvProbe(ecosystems []string) ([]byte, error) {
	type component struct {
		Type    string `json:"type"`
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	}
	doc := struct {
		BOMFormat   string      `json:"bomFormat"`
		SpecVersion string      `json:"specVersion"`
		Version     int         `json:"version"`
		Components  []component `json:"components"`
	}{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1}
	for i, e := range ecosystems {
		p, ok := OSVEcosystems[e]
		if !ok {
			return nil, fmt.Errorf("osv-scanner: unknown ecosystem %q (known: %s)", truncateRunes(e, 64), strings.Join(DefaultOSVEcosystems(), ", "))
		}
		doc.Components = append(doc.Components, component{
			Type: "library", BOMRef: "probe-" + strconv.Itoa(i), Name: osvProbeName, Version: "0.0.0", PURL: p,
		})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	err := enc.Encode(doc)
	return b.Bytes(), err
}

func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r) + "…"
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Upstream []string `json:"upstream"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvDoc struct {
	Results []struct {
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
				PURL      string `json:"purl"`
			} `json:"package"`
			Vulnerabilities []osvVuln `json:"vulnerabilities"`
			Groups          []struct {
				IDs         []string `json:"ids"`
				Aliases     []string `json:"aliases"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

// ParseOSV parses `osv-scanner scan source --format json` output.
func ParseOSV(data []byte) (Result, error) {
	res, _, err := parseOSV(data)
	return res, err
}

// parseOSV also returns the base ecosystems (without release suffix) of every package
// osv-scanner reported.
func parseOSV(data []byte) (Result, []string, error) {
	var doc osvDoc
	if err := decodeLimited(data, &doc); err != nil {
		return Result{}, nil, err
	}
	res := Result{Tool: model.Tool{Name: "osv-scanner"}}
	seen := map[string]bool{}
	var ecosystems []string
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			pkg := p.Package
			if base, _, _ := strings.Cut(pkg.Ecosystem, ":"); base != "" && !seen[base] {
				seen[base] = true
				ecosystems = append(ecosystems, base)
			}
			records := map[string]*osvVuln{}
			for i := range p.Vulnerabilities {
				records[p.Vulnerabilities[i].ID] = &p.Vulnerabilities[i]
			}
			for _, g := range p.Groups {
				if len(g.IDs) == 0 || g.IDs[0] == "" {
					continue
				}
				rm := model.RawMatch{
					Scanner: "osv-scanner", VulnID: g.IDs[0], PURL: pkg.PURL,
					PkgName: pkg.Name, PkgVersion: pkg.Version, PkgType: purlType(pkg.PURL),
					DataSource: "https://osv.dev/vulnerability/" + g.IDs[0],
				}
				aliases := map[string]bool{}
				add := func(ids ...string) {
					for _, a := range ids {
						if a != "" && a != rm.VulnID && !aliases[a] {
							aliases[a] = true
							rm.Aliases = append(rm.Aliases, a)
						}
					}
				}
				add(g.IDs...)
				add(g.Aliases...)
				var label string
				var vectors []grypeCVSS
				for _, id := range g.IDs {
					v := records[id]
					if v == nil {
						continue
					}
					add(v.Aliases...)
					add(v.Upstream...)
					if rm.Title == "" {
						rm.Title = firstLine(cmp.Or(strings.TrimSpace(v.Summary), v.Details), 200)
					}
					for _, s := range v.Severity {
						if major, ok := strings.CutPrefix(s.Type, "CVSS_V"); ok {
							vectors = append(vectors, grypeCVSS{Version: major, Vector: s.Score})
						} else if label == "" {
							label = s.Score // e.g. Ubuntu's priority: "medium"
						}
					}
					if s, ok := v.DatabaseSpecific["severity"].(string); ok && label == "" {
						label = s // e.g. GitHub's "HIGH", "MODERATE"
					}
					rm.FixVersions = append(rm.FixVersions, osvFixed(v, pkg.Name, pkg.Ecosystem)...)
				}
				if score, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil && score > 0 && score <= 10 {
					rm.CVSSScore, rm.Severity = score, severityFromScore(score)
					_, rm.CVSSVector = bestCVSS(vectors)
				} else {
					rm.Severity = model.ParseSeverity(label)
				}
				if len(rm.FixVersions) > 0 {
					rm.FixState = string(model.FixFixed)
				}
				res.Matches = append(res.Matches, rm)
			}
		}
	}
	return res, ecosystems, nil
}

// osvFixed returns the fixed versions of the record's entries for the package: the
// entry of its ecosystem release with its name, or the only entry of that release.
func osvFixed(v *osvVuln, name, ecosystem string) []string {
	var named, same []int
	for i, a := range v.Affected {
		if a.Package.Ecosystem != ecosystem {
			continue
		}
		same = append(same, i)
		if strings.EqualFold(a.Package.Name, name) {
			named = append(named, i)
		}
	}
	pick := named
	if len(pick) == 0 && len(same) == 1 {
		pick = same
	}
	var out []string
	for _, i := range pick {
		for _, r := range v.Affected[i].Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" && len(e.Fixed) <= 128 {
					out = append(out, e.Fixed)
				}
			}
		}
	}
	return out
}

func severityFromScore(s float64) model.Severity {
	switch {
	case s >= 9:
		return model.SeverityCritical
	case s >= 7:
		return model.SeverityHigh
	case s >= 4:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func purlType(p string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	return t
}
