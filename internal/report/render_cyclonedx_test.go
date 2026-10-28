package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/nocs90/shieldmon/internal/store"
)

func cyclonedxSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	for _, f := range []string{"bom-1.6", "spdx", "jsf-0.82"} {
		file, err := os.Open("testdata/cyclonedx/" + f + ".schema.json")
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		// The schemas reference each other by these IDs: no network.
		if err := c.AddResource("http://cyclonedx.org/schema/"+f+".schema.json", doc); err != nil {
			t.Fatal(err)
		}
	}
	sch, err := c.Compile("http://cyclonedx.org/schema/bom-1.6.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return sch
}

func TestInventoryCycloneDX(t *testing.T) {
	src := inventoryFixture()
	// Every digest's syft SBOM is the real trimmed one; c's has a hostile component type.
	for d, list := range src.sboms {
		for i := range list {
			list[i].Path = "syft-dir.cdx.json"
			if list[i].Generator == "trivy" {
				list[i].Path = "trivy-fs.cdx.json"
			}
		}
		src.sboms[d] = list
	}
	read := func(b store.SBOM) ([]byte, error) { return os.ReadFile("../sbom/testdata/" + b.Path) }
	inv, err := BuildInventory(context.Background(), src, InventoryOptions{Now: invNow, ReadSBOM: read, Tool: "shieldmon 1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	f, ok := LookupInventoryFormat("cyclonedx")
	if !ok || !f.Components {
		t.Fatal("cyclonedx is an inventory format that needs components")
	}
	var buf bytes.Buffer
	if err := RenderInventory(&buf, inv, "cyclonedx"); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/inventory.golden.cdx.json"
	if *update {
		if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if want, err := os.ReadFile(golden); err != nil || !bytes.Equal(buf.Bytes(), want) {
		t.Errorf("output differs from %s (%v):\n%s", golden, err, buf.String())
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if err := cyclonedxSchema(t).Validate(inst); err != nil {
		detail := err.Error()
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			if b, jerr := json.Marshal(ve.BasicOutput()); jerr == nil {
				detail = string(b)
			}
		}
		t.Fatalf("not valid CycloneDX 1.6: %s", detail)
	}

	var bom struct {
		Components []struct {
			Type, Name, Version, PURL string
			Hashes                    []struct{ Alg, Content string }
			Properties                []struct{ Name, Value string }
			Components                []struct{ Type, Name string }
		}
		Metadata struct {
			Tools struct {
				Components []struct{ Name, Version string }
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("one container per monitored digest (a, b, c; the retired and unresolved images left out): %d", len(bom.Components))
	}
	a := bom.Components[0]
	aaaa := strings.Repeat("a", 64)
	if a.Type != "container" || a.Version != "sha256:"+aaaa || len(a.Hashes) != 1 || a.Hashes[0].Content != aaaa ||
		len(a.Properties) != 2 || a.PURL != "pkg:oci/app@sha256:"+aaaa+"?arch=amd64&repository_url=registry.test%2Fapp" { // two tags: neither in the PURL
		t.Errorf("container a: %+v", a)
	}
	if len(a.Components) != 6 {
		t.Errorf("syft and trivy components merged: %d", len(a.Components))
	}
	if tool := bom.Metadata.Tools.Components[0]; tool.Name != "shieldmon" || tool.Version != "1.2.3" {
		t.Errorf("tool %+v", tool)
	}
}
