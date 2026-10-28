// Package sbom reads components back from stored CycloneDX SBOMs, for the component
// inventory (#70). SBOMs describe image content and are hostile input: parsing is bounded in
// size, component count, nesting depth and field length, and pure (no I/O).
package sbom

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// Bounds of what is read from one SBOM.
const (
	MaxBytes      = 64 << 20
	MaxComponents = 100_000
	MaxDepth      = 16
	maxField      = 2048
	maxLicenses   = 32
)

// ErrNotCycloneDX is returned for documents that are not CycloneDX JSON.
var ErrNotCycloneDX = errors.New("not a CycloneDX JSON document")

// Component is one package of an image.
type Component struct {
	Name     string   `json:"name"`
	Group    string   `json:"group,omitempty"`
	Version  string   `json:"version,omitempty"`
	Type     string   `json:"type"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
}

// Key identifies a component across SBOMs: its PURL, or its type, group, name and version.
func (c Component) Key() string {
	if c.PURL != "" {
		return c.PURL
	}
	return c.Type + "\x00" + c.Group + "\x00" + c.Name + "\x00" + c.Version
}

type cdxComponent struct {
	Type     string `json:"type"`
	Group    string `json:"group"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl"`
	Licenses []struct {
		License *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Components []cdxComponent `json:"components"`
}

// ParseCycloneDX returns the components of a CycloneDX JSON SBOM (spec 1.2 and later),
// nested ones included, deduplicated by Key, in document order. The document's subject
// (metadata.component, the image itself) is not a component of it. Components without a
// name, or with text fields that are not UTF-8 or too long, are skipped and counted.
func ParseCycloneDX(data []byte) (comps []Component, skipped int, err error) {
	if len(data) > MaxBytes {
		return nil, 0, fmt.Errorf("SBOM larger than %d bytes", MaxBytes)
	}
	var doc struct {
		BOMFormat   string         `json:"bomFormat"`
		SpecVersion string         `json:"specVersion"`
		Components  []cdxComponent `json:"components"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, 0, fmt.Errorf("%w: %w", ErrNotCycloneDX, err)
	}
	if doc.BOMFormat != "CycloneDX" || !strings.HasPrefix(doc.SpecVersion, "1.") {
		return nil, 0, ErrNotCycloneDX
	}
	seen := map[string]bool{}
	var walk func([]cdxComponent, int) error
	walk = func(list []cdxComponent, depth int) error {
		if depth > MaxDepth {
			return fmt.Errorf("components nested deeper than %d", MaxDepth)
		}
		for _, c := range list {
			if len(comps)+skipped >= MaxComponents {
				return fmt.Errorf("more than %d components", MaxComponents)
			}
			comp, ok := component(c)
			switch {
			case !ok:
				skipped++
			case !seen[comp.Key()]:
				seen[comp.Key()] = true
				comps = append(comps, comp)
			}
			if err := walk(c.Components, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(doc.Components, 1); err != nil {
		return nil, skipped, err
	}
	return comps, skipped, nil
}

func component(c cdxComponent) (Component, bool) {
	out := Component{Name: c.Name, Group: c.Group, Version: c.Version, Type: c.Type, PURL: c.PURL}
	for _, f := range []string{out.Name, out.Group, out.Version, out.Type, out.PURL} {
		if len(f) > maxField || !utf8.ValidString(f) {
			return Component{}, false
		}
	}
	if out.Name == "" {
		return Component{}, false
	}
	if out.Type == "" {
		out.Type = "library"
	}
	for _, l := range c.Licenses {
		var v string
		switch {
		case l.Expression != "":
			v = l.Expression
		case l.License != nil && l.License.ID != "":
			v = l.License.ID
		case l.License != nil:
			v = l.License.Name
		}
		if v != "" && len(v) <= maxField && utf8.ValidString(v) && !slices.Contains(out.Licenses, v) && len(out.Licenses) < maxLicenses {
			out.Licenses = append(out.Licenses, v)
		}
	}
	return out, true
}
