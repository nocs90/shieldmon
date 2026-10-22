// Package normalize turns raw scanner matches into ShieldMon's internal
// schema: canonical PURLs, canonical vulnerability IDs (CVE preferred over
// GHSA/distro aliases) and one Match per (PURL, vulnerability) per digest.
package normalize

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/nocs90/shieldmon/internal/model"
)

// keptQualifiers are PURL qualifiers that are part of a package's identity.
// Everything else (arch, distro, package-id, upstream, ...) varies between
// scanners for the same installed package and is dropped.
// validType is the PURL spec grammar for the type component.
var validType = regexp.MustCompile(`^[a-z][a-z0-9.+-]*$`)

var keptQualifiers = map[string]bool{"epoch": true}

// CanonicalPURL returns the canonical PURL with version and the version-less
// package key. If the PURL cannot be parsed, a pkg:generic form is built from
// the fallback name/version so that the match is still tracked.
func CanonicalPURL(raw, fallbackType, fallbackName, fallbackVersion string) (purl, pkgKey string) {
	p, err := packageurl.FromString(strings.TrimSpace(raw))
	if err != nil || p.Name == "" {
		p = packageurl.PackageURL{Type: fallbackType, Name: fallbackName, Version: fallbackVersion}
	}
	// Types come from hostile scanner output: anything outside the PURL spec
	// grammar would yield an unstable key, so it collapses to "generic".
	p.Type = strings.ToLower(p.Type)
	if !validType.MatchString(p.Type) {
		p.Type = "generic"
	}
	if p.Name == "" {
		p.Name = "unknown"
	}
	switch p.Type {
	case "pypi":
		// PEP 503 name normalization.
		p.Name = strings.ReplaceAll(strings.ToLower(p.Name), "_", "-")
	case "npm", "apk", "deb", "gem":
		p.Name = strings.ToLower(p.Name)
		p.Namespace = strings.ToLower(p.Namespace)
	}
	var q packageurl.Qualifiers
	for _, kv := range p.Qualifiers {
		if keptQualifiers[kv.Key] && kv.Value != "" {
			q = append(q, kv)
		}
	}
	slices.SortFunc(q, func(a, b packageurl.Qualifier) int { return cmp.Compare(a.Key, b.Key) })
	p.Qualifiers = q
	p.Subpath = ""
	purl = p.ToString()
	p.Version = ""
	pkgKey = p.ToString()
	return purl, pkgKey
}

// CanonicalVulnID upper/lower-cases well-known ID prefixes consistently.
func CanonicalVulnID(id string) string {
	id = strings.TrimSpace(id)
	up := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(up, "CVE-"):
		return up
	case strings.HasPrefix(up, "GHSA-"):
		return "GHSA-" + strings.ToLower(id[5:])
	default:
		return id
	}
}

func isCVE(id string) bool { return strings.HasPrefix(id, "CVE-") }

// Merge normalizes and deduplicates raw matches from any number of scanners
// for a single digest. The output is sorted by (PURL, VulnID).
func Merge(raw []model.RawMatch) []model.Match {
	type item struct {
		m       model.Match
		aliases map[string]bool
	}
	// Pass 1: canonicalize identifiers.
	items := make([]item, 0, len(raw))
	for _, r := range raw {
		purl, key := CanonicalPURL(r.PURL, r.PkgType, r.PkgName, r.PkgVersion)
		id := CanonicalVulnID(r.VulnID)
		al := map[string]bool{}
		for _, a := range r.Aliases {
			if a = CanonicalVulnID(a); a != "" && a != id {
				al[a] = true
			}
		}
		var scanners []string
		if r.Scanner != "" {
			scanners = []string{r.Scanner}
		}
		items = append(items, item{
			m: model.Match{
				VulnID: id, PURL: purl, PkgKey: key,
				PkgName: r.PkgName, PkgVersion: r.PkgVersion, PkgType: r.PkgType,
				Severity: r.Severity, CVSSScore: r.CVSSScore, CVSSVector: r.CVSSVector,
				EPSS: r.EPSS, KEV: r.KEV, FixVersions: r.FixVersions, FixState: model.ParseFixState(r.FixState),
				Scanners: scanners, Title: r.Title,
			},
			aliases: al,
		})
	}

	// Pass 2: per package, map each non-CVE ID to a CVE when the union of its
	// aliases (across all scanners) names exactly one CVE. Advisories that
	// cover several CVEs are left alone: collapsing them would hide CVEs.
	aliasUnion := map[string]map[string]bool{} // purl|id -> aliases
	for _, it := range items {
		k := it.m.PURL + "|" + it.m.VulnID
		if aliasUnion[k] == nil {
			aliasUnion[k] = map[string]bool{}
		}
		for a := range it.aliases {
			aliasUnion[k][a] = true
		}
	}
	for i := range items {
		it := &items[i]
		if isCVE(it.m.VulnID) {
			continue
		}
		var cves []string
		for a := range aliasUnion[it.m.PURL+"|"+it.m.VulnID] {
			if isCVE(a) {
				cves = append(cves, a)
			}
		}
		if len(cves) == 1 {
			it.aliases[it.m.VulnID] = true
			delete(it.aliases, cves[0])
			it.m.VulnID = cves[0]
		}
	}

	// Pass 3: merge by (PURL, VulnID).
	merged := map[string]*item{}
	var order []string
	for _, it := range items {
		k := it.m.Key()
		cur, ok := merged[k]
		if !ok {
			c := it
			merged[k] = &c
			order = append(order, k)
			continue
		}
		mergeInto(&cur.m, it.m)
		for a := range it.aliases {
			cur.aliases[a] = true
		}
	}

	out := make([]model.Match, 0, len(order))
	for _, k := range order {
		it := merged[k]
		delete(it.aliases, it.m.VulnID)
		it.m.Aliases = sortedKeys(it.aliases)
		it.m.Scanners = sortedUnique(it.m.Scanners)
		it.m.FixVersions = sortedUnique(it.m.FixVersions)
		if len(it.m.FixVersions) > 0 {
			it.m.FixState = model.FixFixed
		} else if it.m.FixState == "" {
			it.m.FixState = model.FixUnknown
		}
		out = append(out, it.m)
	}
	slices.SortFunc(out, func(a, b model.Match) int {
		return cmp.Or(cmp.Compare(a.PURL, b.PURL), cmp.Compare(a.VulnID, b.VulnID))
	})
	return out
}

// mergeInto folds b into a conservatively: highest severity/score wins, sets
// are unioned, and the first non-empty descriptive field is kept.
func mergeInto(a *model.Match, b model.Match) {
	if b.Severity > a.Severity {
		a.Severity = b.Severity
	}
	if b.CVSSScore > a.CVSSScore {
		a.CVSSScore, a.CVSSVector = b.CVSSScore, b.CVSSVector
	}
	a.EPSS = max(a.EPSS, b.EPSS)
	a.KEV = a.KEV || b.KEV
	a.FixVersions = append(a.FixVersions, b.FixVersions...)
	a.FixState = mergeFixState(a.FixState, b.FixState)
	a.Scanners = append(a.Scanners, b.Scanners...)
	if a.Title == "" {
		a.Title = b.Title
	}
	if a.PkgType == "" {
		a.PkgType = b.PkgType
	}
}

// mergeFixState prefers the most actionable answer: any scanner knowing a
// fix wins; otherwise a vendor "won't fix" beats "not fixed yet".
func mergeFixState(a, b model.FixState) model.FixState {
	rank := map[model.FixState]int{model.FixUnknown: 0, model.FixNotFixed: 1, model.FixWontFix: 2, model.FixFixed: 3}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func sortedKeys(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
