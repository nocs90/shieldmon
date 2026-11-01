package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"
)

func init() {
	RegisterInventoryFormat(InventoryFormat{
		Name:        "cyclonedx",
		Description: "one CycloneDX 1.6 BOM of every monitored image (a container component per digest) and its components",
		Components:  true,
		Render:      renderInventoryCycloneDX,
	})
}

// MaxBOMComponents bounds the aggregated BOM: beyond it the inventory is too large for one
// document, and per-image SBOMs (shieldmon sbom export) are the better tool.
const MaxBOMComponents = 500_000

// cdxTypes are the component types CycloneDX 1.6 defines; anything else from an SBOM becomes
// a library.
var cdxTypes = []string{
	"application", "framework", "library", "container", "platform", "operating-system", "device",
	"device-driver", "firmware", "file", "machine-learning-model", "data", "cryptographic-asset",
}

type (
	cdxBOM struct {
		BOMFormat    string         `json:"bomFormat"`
		SpecVersion  string         `json:"specVersion"`
		SerialNumber string         `json:"serialNumber"`
		Version      int            `json:"version"`
		Metadata     cdxMetadata    `json:"metadata"`
		Components   []cdxComponent `json:"components"`
	}
	cdxMetadata struct {
		Timestamp string `json:"timestamp"`
		Tools     struct {
			Components []cdxComponent `json:"components"`
		} `json:"tools"`
		Component cdxComponent `json:"component"`
	}
	cdxComponent struct {
		Type       string         `json:"type"`
		BOMRef     string         `json:"bom-ref,omitempty"`
		Group      string         `json:"group,omitempty"`
		Name       string         `json:"name"`
		Version    string         `json:"version,omitempty"`
		PURL       string         `json:"purl,omitempty"`
		Hashes     []cdxHash      `json:"hashes,omitempty"`
		Licenses   []cdxLicense   `json:"licenses,omitempty"`
		Properties []cdxProperty  `json:"properties,omitempty"`
		Components []cdxComponent `json:"components,omitempty"`
	}
	cdxHash struct {
		Alg     string `json:"alg"`
		Content string `json:"content"`
	}
	cdxLicense struct {
		License struct {
			Name string `json:"name"`
		} `json:"license"`
	}
	cdxProperty struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
)

func renderInventoryCycloneDX(w io.Writer, inv Inventory) error {
	tool := cdxComponent{Type: "application", Name: "shieldmon"}
	if name, version, ok := strings.Cut(inv.Tool, " "); ok {
		tool.Name, tool.Version = name, version
	}
	bom := cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1, Components: []cdxComponent{}}
	bom.Metadata.Timestamp = inv.GeneratedAt.UTC().Format(time.RFC3339)
	bom.Metadata.Tools.Components = []cdxComponent{tool}
	bom.Metadata.Component = cdxComponent{Type: "application", BOMRef: "monitored-images", Name: "monitored container images"}

	// One container per digest: targets resolving to the same digest are the same image.
	byDigest := map[string]*cdxComponent{}
	var order []string
	total := 0
	for _, img := range inv.Images {
		if img.Digest == "" || !img.RetiredAt.IsZero() {
			continue
		}
		target := cdxProperty{Name: "shieldmon:target", Value: img.Ref + " (" + img.Platform + ")"}
		if c, ok := byDigest[img.Digest]; ok {
			// Several tags for one digest: the PURL names none of them (the properties do).
			c.Properties = append(c.Properties, target)
			untagged := img
			untagged.Ref = ""
			c.PURL = ociPURL(untagged)
			continue
		}
		c := &cdxComponent{
			Type: "container", BOMRef: img.Digest, Name: img.Repository, Version: img.Digest,
			PURL: ociPURL(img), Properties: []cdxProperty{target},
		}
		if c.Name == "" {
			c.Name = img.Ref
		}
		if alg, sum, ok := strings.Cut(img.Digest, ":"); ok && alg == "sha256" && len(sum) == 64 && isHexString(sum) {
			c.Hashes = []cdxHash{{Alg: "SHA-256", Content: sum}}
		}
		for _, comp := range img.Components {
			if total++; total > MaxBOMComponents {
				return fmt.Errorf("more than %d components: export SBOMs per image instead (shieldmon sbom export)", MaxBOMComponents)
			}
			cc := cdxComponent{Type: comp.Type, Group: comp.Group, Name: comp.Name, Version: comp.Version, PURL: comp.PURL}
			if !slices.Contains(cdxTypes, cc.Type) {
				cc.Type = "library"
			}
			for _, l := range comp.Licenses {
				var lic cdxLicense
				lic.License.Name = l
				cc.Licenses = append(cc.Licenses, lic)
			}
			c.Components = append(c.Components, cc)
		}
		byDigest[img.Digest] = c
		order = append(order, img.Digest)
	}
	slices.Sort(order)
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00", bom.Metadata.Timestamp)
	for _, d := range order {
		c := byDigest[d]
		slices.SortFunc(c.Properties, func(a, b cdxProperty) int { return strings.Compare(a.Value, b.Value) })
		bom.Components = append(bom.Components, *c)
		fmt.Fprintf(h, "%s\x00", d)
	}
	bom.SerialNumber = "urn:uuid:" + uuidFrom(h.Sum(nil))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// ociPURL is the package URL of an image digest: pkg:oci/NAME@DIGEST?repository_url=…&tag=…&arch=….
func ociPURL(img Image) string {
	repo := img.Repository
	if repo == "" {
		return ""
	}
	name := strings.ToLower(repo[strings.LastIndex(repo, "/")+1:])
	q := packageurl.Qualifiers{{Key: "repository_url", Value: repo}}
	if tag := refTag(img.Ref); tag != "" {
		q = append(q, packageurl.Qualifier{Key: "tag", Value: tag})
	}
	if _, arch, ok := strings.Cut(img.Platform, "/"); ok {
		q = append(q, packageurl.Qualifier{Key: "arch", Value: strings.ReplaceAll(arch, "/", "")})
	}
	return packageurl.NewPackageURL("oci", "", name, img.Digest, q, "").ToString()
}

func isHexString(s string) bool {
	for i := range len(s) {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

// refTag is the tag of an image reference, "" for a digest reference.
func refTag(ref string) string {
	if strings.Contains(ref, "@") {
		return ""
	}
	i := strings.LastIndex(ref, ":")
	if i < 0 || i < strings.LastIndex(ref, "/") {
		return ""
	}
	return ref[i+1:]
}

// uuidFrom formats 16 bytes of a hash as an RFC 9562 UUID (version 8, custom), so that the
// same inventory gets the same serial number.
func uuidFrom(sum []byte) string {
	b := make([]byte, 16)
	copy(b, sum)
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}
