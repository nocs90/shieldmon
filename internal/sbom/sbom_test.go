package sbom

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseSyft(t *testing.T) {
	comps, skipped, err := ParseCycloneDX(fixture(t, "syft-dir.cdx.json"))
	if err != nil || skipped != 0 {
		t.Fatal(err, skipped)
	}
	var keys []string
	for _, c := range comps {
		keys = append(keys, c.Key())
	}
	want := []string{
		"pkg:github/actions/checkout@v6.1.0",
		"pkg:golang/github.com/google/go-containerregistry@v0.22.1",
		"pkg:golang/golang.org/x/sys@v0.48.0",
		"pkg:golang/stdlib@1.27.2",
	}
	if !reflect.DeepEqual(keys, want) {
		t.Errorf("components (deduplicated by PURL, in document order):\n got %q\nwant %q", keys, want)
	}
}

func TestParseTrivy(t *testing.T) {
	comps, _, err := ParseCycloneDX(fixture(t, "trivy-fs.cdx.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 4 || comps[0].Name != "go.mod" || comps[0].Type != "application" || comps[0].PURL != "" {
		t.Fatalf("an application without version or PURL is a component too: %+v", comps)
	}
	if md := comps[3]; md.Name != "cloud.google.com/go/compute/metadata" || !reflect.DeepEqual(md.Licenses, []string{"Apache-2.0"}) {
		t.Errorf("licenses: %+v", md)
	}
}

func TestParseRejectsHostileSBOMs(t *testing.T) {
	deep := strings.Repeat(`{"name":"n","components":[`, MaxDepth+1) + strings.Repeat(`]}`, MaxDepth+1)
	for what, doc := range map[string]string{
		"not JSON":    "<html>",
		"SPDX":        `{"spdxVersion":"SPDX-2.3","packages":[]}`,
		"CycloneDX 2": `{"bomFormat":"CycloneDX","specVersion":"2.0","components":[]}`,
		"wrong types": `{"bomFormat":"CycloneDX","specVersion":"1.6","components":"x"}`,
		"too deep":    `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[` + deep + `]}`,
		"oversized":   `{"bomFormat":"CycloneDX","specVersion":"1.6","x":"` + strings.Repeat("a", MaxBytes) + `"}`,
	} {
		if _, _, err := ParseCycloneDX([]byte(doc)); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
		{"name":""},
		{"name":"` + strings.Repeat("x", maxField+1) + `"},
		{"name":"ok","version":"1","licenses":[{"expression":"MIT OR Apache-2.0"},{"license":{"name":"Custom"}},{"license":{"id":"MIT"}},{"license":{"id":"MIT"}}]}
	]}`
	comps, skipped, err := ParseCycloneDX([]byte(doc))
	if err != nil || skipped != 2 || len(comps) != 1 || comps[0].Type != "library" ||
		!reflect.DeepEqual(comps[0].Licenses, []string{"MIT OR Apache-2.0", "Custom", "MIT"}) {
		t.Errorf("invalid components are skipped and counted: %+v %d %v", comps, skipped, err)
	}
}

// layeredSBOM has the layer properties of image SBOMs: syft writes "syft:location:N:layerID"
// (the cyclonedx tag of its FileSystemID), trivy "aquasecurity:trivy:LayerDiffID".
const layeredSBOM = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[
 {"type":"library","name":"zlib","version":"1.3-r0","purl":"pkg:apk/alpine/zlib@1.3-r0","properties":[
  {"name":"syft:location:0:layerID","value":"sha256:` + layerA + `"},
  {"name":"syft:location:0:path","value":"/lib/apk/db/installed"},
  {"name":"syft:location:1:layerID","value":"sha256:` + layerB + `"}]},
 {"type":"library","name":"zlib","version":"1.3-r0","purl":"pkg:apk/alpine/zlib@1.3-r0","properties":[
  {"name":"aquasecurity:trivy:LayerDiffID","value":"sha256:` + layerC + `"}]},
 {"type":"library","name":"evil","version":"1","properties":[
  {"name":"syft:location:0:layerID","value":"sha256:../../etc/passwd"},
  {"name":"aquasecurity:trivy:LayerDiffID","value":"sha256:` + layerA + `\n"},
  {"name":"other:layerID","value":"sha256:` + layerA + `"}]}]}`

const (
	layerA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	layerB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	layerC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestParseLayers(t *testing.T) {
	comps, _, err := ParseCycloneDX([]byte(layeredSBOM))
	if err != nil {
		t.Fatal(err)
	}
	if len(comps) != 2 {
		t.Fatalf("components = %+v", comps)
	}
	want := []string{"sha256:" + layerA, "sha256:" + layerB, "sha256:" + layerC}
	if !reflect.DeepEqual(comps[0].Layers, want) {
		t.Errorf("layers = %v: every location, merged across duplicates", comps[0].Layers)
	}
	if comps[1].Layers != nil {
		t.Errorf("malformed or foreign layer properties are ignored: %v", comps[1].Layers)
	}
}

func FuzzParseCycloneDX(f *testing.F) {
	f.Add(fixture(f, "syft-dir.cdx.json"))
	f.Add(fixture(f, "trivy-fs.cdx.json"))
	f.Add([]byte(layeredSBOM))
	f.Fuzz(func(t *testing.T, data []byte) {
		comps, _, err := ParseCycloneDX(data)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, c := range comps {
			if c.Name == "" || len(c.Name) > maxField || seen[c.Key()] {
				t.Fatalf("invalid or duplicate component accepted: %+v", c)
			}
			if len(c.Layers) > maxLayers {
				t.Fatalf("unbounded layers: %d", len(c.Layers))
			}
			for _, l := range c.Layers {
				if !isLayerDigest(l) {
					t.Fatalf("invalid layer accepted: %q", l)
				}
			}
			seen[c.Key()] = true
		}
	})
}
