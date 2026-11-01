package oci

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// derived builds an image on base, as FROM base plus one layer would.
func derived(t *testing.T, base v1.Image, created time.Time) v1.Image {
	t.Helper()
	layer, err := random.Layer(256, "application/vnd.oci.image.layer.v1.tar+gzip")
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(base, layer)
	if err != nil {
		t.Fatal(err)
	}
	img, err = mutate.CreatedAt(img, v1.Time{Time: created})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func diffIDs(t *testing.T, img v1.Image) []string {
	t.Helper()
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range cfg.RootFS.DiffIDs {
		out = append(out, d.String())
	}
	return out
}

func TestInspectReadsLayersAndBaseAnnotations(t *testing.T) {
	reg := testRegistry(t)
	base, _ := random.Image(512, 2)
	base = withPlatform(t, base, "linux", "amd64")
	baseDigest := push(t, reg+"/base:1", base)
	created := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	app := mutate.Annotations(derived(t, base, created), map[string]string{
		AnnotationBaseName:   reg + "/base:1",
		AnnotationBaseDigest: baseDigest.String(),
	}).(v1.Image)
	appDigest := push(t, reg+"/app:1", app)

	info, err := Inspect(context.Background(), reg+"/app:1", opts())
	if err != nil {
		t.Fatal(err)
	}
	if info.Digest != appDigest.String() || !info.Created.Equal(created) || info.Platform != amd64 {
		t.Errorf("info = %+v", info)
	}
	if len(info.DiffIDs) != 3 || !slices.Equal(info.DiffIDs[:2], diffIDs(t, base)) {
		t.Errorf("diff_ids = %v: the base's layers come first", info.DiffIDs)
	}
	if info.BaseName != reg+"/base:1" || info.BaseRepository != reg+"/base" || info.BaseDigest != baseDigest.String() || len(info.Problems) != 0 {
		t.Errorf("base annotations = %q %q %q %v", info.BaseName, info.BaseRepository, info.BaseDigest, info.Problems)
	}
}

func TestInspectIndexDescriptorAnnotations(t *testing.T) {
	reg := testRegistry(t)
	base, _ := random.Image(512, 1)
	app := withPlatform(t, derived(t, base, time.Time{}), "linux", "amd64")
	idx := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{Add: app, Descriptor: v1.Descriptor{
		Platform:    &v1.Platform{OS: "linux", Architecture: "amd64"},
		Annotations: map[string]string{AnnotationBaseName: "docker.io/library/alpine:3.20"},
	}})
	ref, _ := name.ParseReference(reg+"/multi:1", name.Insecure)
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(context.Background(), reg+"/multi:1", opts())
	if err != nil {
		t.Fatal(err)
	}
	appDigest, _ := app.Digest()
	if info.Digest != appDigest.String() || info.IndexDigest == "" || info.BaseName != "index.docker.io/library/alpine:3.20" || info.BaseDigest != "" {
		t.Errorf("info = %+v", info)
	}
	if !info.Created.IsZero() {
		t.Errorf("created = %v", info.Created)
	}
}

func TestInspectIgnoresHostileAnnotations(t *testing.T) {
	for _, c := range []struct {
		name        string
		annotations map[string]string
		wantName    string
		wantDigest  string
		problem     string
	}{
		{"too long", map[string]string{AnnotationBaseName: "registry.test/" + strings.Repeat("a", 600) + ":1"}, "", "", "longer than 512"},
		{"not a reference", map[string]string{AnnotationBaseName: "-oops $(id)"}, "", "", "not an image reference"},
		{"bad digest", map[string]string{AnnotationBaseName: "registry.test/b:1", AnnotationBaseDigest: "md5:abc"}, "registry.test/b:1", "", "not a sha256 digest"},
		{"digest reference", map[string]string{AnnotationBaseName: "registry.test/b@sha256:" + strings.Repeat("a", 64)}, "", "sha256:" + strings.Repeat("a", 64), ""},
		{"digest without repository", map[string]string{AnnotationBaseDigest: "sha256:" + strings.Repeat("b", 64)}, "", "", ""},
	} {
		var info ImageInfo
		info.baseAnnotations(c.annotations)
		problems := strings.Join(info.Problems, ";")
		if info.BaseName != c.wantName || info.BaseDigest != c.wantDigest || (c.problem == "") != (problems == "") || !strings.Contains(problems, c.problem) {
			t.Errorf("%s: %q %q %q", c.name, info.BaseName, info.BaseDigest, problems)
		}
	}
}

func TestInspectEnforcesLimits(t *testing.T) {
	reg := testRegistry(t)
	img, _ := random.Image(256, 4)
	push(t, reg+"/many:1", withPlatform(t, img, "linux", "amd64"))
	o := opts()
	o.Limits = DefaultLimits
	o.Limits.MaxLayers = 3
	if _, err := Inspect(context.Background(), reg+"/many:1", o); !errors.Is(err, ErrLimit) {
		t.Errorf("4 layers over a limit of 3: %v", err)
	}
}
