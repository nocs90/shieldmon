package report

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nocs90/shieldmon/internal/sbom"
	"github.com/nocs90/shieldmon/internal/store"
)

// ComponentSource is the subset of the store the component inventory needs.
type ComponentSource interface {
	ListTargets(ctx context.Context) ([]store.Target, error)
	SBOMs(ctx context.Context, digest string) ([]store.SBOM, error)
}

// SBOMReader returns a stored SBOM's bytes after checking its integrity (engine.ReadSBOM).
type SBOMReader func(store.SBOM) ([]byte, error)

// ComponentInventory lists the components of the monitored images' current digests.
type ComponentInventory struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Components  []ComponentRow `json:"components"`
	// Problems are SBOMs that could not be read: their images' components may be missing.
	Problems []string `json:"problems,omitempty"`
}

// ComponentRow is one component and the images that contain it.
type ComponentRow struct {
	sbom.Component
	Images  []string `json:"images"`
	Digests []string `json:"digests"`
}

// BuildComponents reads the CycloneDX SBOMs of the current digests of the targets keep selects
// (all when nil) and merges their components, by PURL (or type, group, name and version).
func BuildComponents(ctx context.Context, src ComponentSource, read SBOMReader, keep func(store.Target) bool, now time.Time) (ComponentInventory, error) {
	ci := ComponentInventory{GeneratedAt: now.UTC(), Components: []ComponentRow{}}
	targets, err := src.ListTargets(ctx)
	if err != nil {
		return ci, err
	}
	rows := map[string]*ComponentRow{}
	byDigest := map[string][]sbom.Component{}
	for _, t := range targets {
		if t.CurrentDigest == "" || (keep != nil && !keep(t)) {
			continue
		}
		comps, ok := byDigest[t.CurrentDigest]
		if !ok {
			if comps, err = digestComponents(ctx, src, read, t.CurrentDigest, &ci.Problems); err != nil {
				return ci, err
			}
			byDigest[t.CurrentDigest] = comps
		}
		image := t.Ref + " (" + t.Platform + ")"
		for _, c := range comps {
			r, ok := rows[c.Key()]
			if !ok {
				r = &ComponentRow{Component: c}
				rows[c.Key()] = r
			}
			if !slices.Contains(r.Images, image) {
				r.Images = append(r.Images, image)
			}
			if !slices.Contains(r.Digests, t.CurrentDigest) {
				r.Digests = append(r.Digests, t.CurrentDigest)
			}
		}
	}
	for _, r := range rows {
		slices.Sort(r.Images)
		slices.Sort(r.Digests)
		ci.Components = append(ci.Components, *r)
	}
	sort.Slice(ci.Components, func(i, j int) bool {
		a, b := ci.Components[i], ci.Components[j]
		return a.Name+"\x00"+a.Version+"\x00"+a.Key() < b.Name+"\x00"+b.Version+"\x00"+b.Key()
	})
	slices.Sort(ci.Problems)
	return ci, nil
}

// digestComponents merges the components of a digest's CycloneDX SBOMs (one per generator).
func digestComponents(ctx context.Context, src ComponentSource, read SBOMReader, digest string, problems *[]string) ([]sbom.Component, error) {
	list, err := src.SBOMs(ctx, digest)
	if err != nil {
		return nil, err
	}
	var out []sbom.Component
	seen := map[string]bool{}
	for _, b := range list {
		if b.Format != "cyclonedx-json" {
			continue
		}
		data, err := read(b)
		var comps []sbom.Component
		if err == nil {
			comps, _, err = sbom.ParseCycloneDX(data)
		}
		if err != nil {
			*problems = append(*problems, fmt.Sprintf("%s %s: %v", digest, b.Generator, err))
			continue
		}
		for _, c := range comps {
			if !seen[c.Key()] {
				seen[c.Key()] = true
				out = append(out, c)
			}
		}
	}
	return out, nil
}

// MatchComponent reports whether c is what query names: a PURL (exact, or any version when
// the query has none), NAME@VERSION, or NAME (case-insensitive; group/name for grouped
// components).
func MatchComponent(c sbom.Component, query string) bool {
	if strings.HasPrefix(query, "pkg:") {
		if c.PURL == query {
			return true
		}
		return !strings.ContainsAny(query, "@?#") && purlBase(c.PURL) == query
	}
	name, version, hasVersion := strings.Cut(query, "@")
	if name == "" {
		return false
	}
	named := strings.EqualFold(c.Name, name) || (c.Group != "" && strings.EqualFold(c.Group+"/"+c.Name, name))
	return named && (!hasVersion || c.Version == version)
}

// purlBase is a package URL without version, qualifiers and subpath.
func purlBase(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	if i := strings.LastIndex(purl, "@"); i > strings.LastIndex(purl, "/") {
		purl = purl[:i]
	}
	return purl
}

// Filter returns the inventory restricted to the components query names.
func (ci ComponentInventory) Filter(query string) ComponentInventory {
	out := ci
	out.Components = []ComponentRow{}
	for _, r := range ci.Components {
		if MatchComponent(r.Component, query) {
			out.Components = append(out.Components, r)
		}
	}
	return out
}

var componentHeader = []string{"name", "group", "version", "type", "purl", "licenses", "images", "digests"}

// RenderComponents writes the component inventory as csv or json.
func RenderComponents(w io.Writer, ci ComponentInventory, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(ci)
	case "csv":
		cw := csv.NewWriter(w)
		if err := cw.Write(componentHeader); err != nil {
			return err
		}
		for _, r := range ci.Components {
			rec := []string{r.Name, r.Group, r.Version, r.Type, r.PURL, strings.Join(r.Licenses, "; "), strings.Join(r.Images, "; "), strings.Join(r.Digests, "; ")}
			for i, v := range rec {
				rec[i] = CSVSafe(oneLine(v))
			}
			if err := cw.Write(rec); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	}
	return fmt.Errorf("unknown component format %q (supported: csv, json)", format)
}
