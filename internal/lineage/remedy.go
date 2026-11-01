package lineage

import (
	"slices"

	"github.com/nocs90/shieldmon/internal/normalize"
	"github.com/nocs90/shieldmon/internal/sbom"
)

// Remedy is what removes a finding from an image (docs/adr/0023-fixable-by-rebuild.md).
type Remedy string

// Remedies.
const (
	// RemedyApplication: the package is only in the image's own layers.
	RemedyApplication Remedy = "application"
	// RemedyRebuild: the package comes from the base, and the newest base has another
	// version of it, or none.
	RemedyRebuild Remedy = "rebuild"
	// RemedyBase: the package comes from the base, and the newest base has the same version.
	RemedyBase Remedy = "base"
	// RemedyUnknown: no recorded layer, no proven base, or no SBOM of the newest base.
	RemedyUnknown Remedy = "unknown"
)

// Packages classifies the packages of one image against its base.
type Packages struct {
	// remedies by canonical PURL with version
	remedies map[string]Remedy
}

// Classify gives the remedy of each package of an image: image are the components of its
// SBOMs (with their layers), baseLayers the image layers its proven base shares (empty when
// none is proven), newest the components of the newest base's SBOMs (nil when it has none).
func Classify(image []sbom.Component, baseLayers []string, newest []sbom.Component) Packages {
	versions := map[string][]string{} // newest base: package key -> versions
	for _, c := range newest {
		purl, key := canonical(c)
		versions[key] = append(versions[key], purl)
	}
	// Every layer a package is recorded in, by any generator: syft records the layer holding
	// the package database it read (for OS packages, the last layer that rewrote it), trivy the
	// layer that added the package. The package is the base's when any of them is a base layer.
	layers := map[string][]string{}
	keys := map[string]string{}
	var order []string
	for _, c := range image {
		purl, key := canonical(c)
		if _, ok := keys[purl]; !ok {
			keys[purl] = key
			order = append(order, purl)
		}
		layers[purl] = append(layers[purl], c.Layers...)
	}
	p := Packages{remedies: map[string]Remedy{}}
	for _, purl := range order {
		r := RemedyUnknown
		switch ls := layers[purl]; {
		case len(ls) == 0 || len(baseLayers) == 0:
		case !slices.ContainsFunc(ls, func(l string) bool { return slices.Contains(baseLayers, l) }):
			r = RemedyApplication
		case newest == nil:
		case slices.Contains(versions[keys[purl]], purl):
			r = RemedyBase
		default:
			r = RemedyRebuild
		}
		p.remedies[purl] = r
	}
	return p
}

// Of gives the remedy of a finding's package, by its canonical PURL (with version).
func (p Packages) Of(purl string) Remedy {
	if r, ok := p.remedies[purl]; ok {
		return r
	}
	return RemedyUnknown
}

func canonical(c sbom.Component) (purl, key string) {
	return normalize.CanonicalPURL(c.PURL, c.Type, c.Name, c.Version)
}
