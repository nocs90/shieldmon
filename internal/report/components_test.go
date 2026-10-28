package report

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nocs90/shieldmon/internal/sbom"
	"github.com/nocs90/shieldmon/internal/store"
)

type fakeComponents struct {
	targets []store.Target
	sboms   map[string][]store.SBOM
}

func (f fakeComponents) ListTargets(context.Context) ([]store.Target, error) { return f.targets, nil }

func (f fakeComponents) SBOMs(_ context.Context, d string) ([]store.SBOM, error) {
	return f.sboms[d], nil
}

func TestComponentInventory(t *testing.T) {
	src := fakeComponents{
		targets: []store.Target{
			{Ref: "registry.test/app:prod", Platform: "linux/amd64", CurrentDigest: "sha256:aaaa"},
			{Ref: "registry.test/app:latest", Platform: "linux/amd64", CurrentDigest: "sha256:aaaa"},
			{Ref: "registry.test/api:1", Platform: "linux/arm64", CurrentDigest: "sha256:bbbb"},
			{Ref: "registry.test/new:1", Platform: "linux/amd64"},
		},
		sboms: map[string][]store.SBOM{
			"sha256:aaaa": {
				{Generator: "syft", Format: "cyclonedx-json", Path: "syft-dir.cdx.json"},
				{Generator: "syft", Format: "spdx-json", Path: "never-read"},
				{Generator: "trivy", Format: "cyclonedx-json", Path: "trivy-fs.cdx.json"},
			},
			"sha256:bbbb": {{Generator: "trivy", Format: "cyclonedx-json", Path: "trivy-fs.cdx.json"}, {Generator: "syft", Format: "cyclonedx-json", Path: "tampered"}},
		},
	}
	read := func(b store.SBOM) ([]byte, error) {
		if b.Path == "tampered" || b.Path == "never-read" {
			return nil, errors.New("SHA-256 differs from the recorded one")
		}
		return os.ReadFile("../sbom/testdata/" + b.Path)
	}
	ci, err := BuildComponents(context.Background(), src, read, nil, invNow)
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]ComponentRow{}
	for _, r := range ci.Components {
		byKey[r.Key()] = r
	}
	ggcr := byKey["pkg:golang/github.com/google/go-containerregistry@v0.22.1"]
	if strings.Join(ggcr.Images, ",") != "registry.test/api:1 (linux/arm64),registry.test/app:latest (linux/amd64),registry.test/app:prod (linux/amd64)" ||
		len(ggcr.Digests) != 2 {
		t.Errorf("found by both generators in both digests, listed once: %+v", ggcr)
	}
	if checkout := byKey["pkg:github/actions/checkout@v6.1.0"]; len(checkout.Images) != 2 {
		t.Errorf("syft-only component: %+v", checkout)
	}
	if len(ci.Components) != 6 {
		t.Errorf("components = %d, want 6 (4 from syft, 2 more from trivy)", len(ci.Components))
	}
	if len(ci.Problems) != 1 || !strings.Contains(ci.Problems[0], "sha256:bbbb syft") {
		t.Errorf("an SBOM that fails its integrity check is reported, not used: %q", ci.Problems)
	}

	only, err := BuildComponents(context.Background(), src, read, func(t store.Target) bool { return t.Ref == "registry.test/api:1" }, invNow)
	if err != nil || len(only.Components) != 4 {
		t.Errorf("--target keeps one image: %d %v", len(only.Components), err)
	}

	var buf bytes.Buffer
	if err := RenderComponents(&buf, ci, "csv"); err != nil {
		t.Fatal(err)
	}
	if recs, err := csv.NewReader(&buf).ReadAll(); err != nil || len(recs) != 7 {
		t.Errorf("csv: %d rows %v", len(recs), err)
	}
}

func TestMatchComponent(t *testing.T) {
	c := sbom.Component{Name: "log4j-core", Group: "org.apache.logging.log4j", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"}
	for q, want := range map[string]bool{
		"log4j-core":                          true,
		"LOG4J-CORE":                          true,
		"log4j-core@2.14.1":                   true,
		"log4j-core@2.17.0":                   false,
		"org.apache.logging.log4j/log4j-core": true,
		"pkg:maven/org.apache.logging.log4j/log4j-core":                 true,
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar": true,
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0":          false,
		"pkg:maven/org.apache.logging.log4j/log4j-api":                  false,
		"log4j":   false,
		"@2.14.1": false,
	} {
		if got := MatchComponent(c, q); got != want {
			t.Errorf("%q: %t, want %t", q, got, want)
		}
	}
}
