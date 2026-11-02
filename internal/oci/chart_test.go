package oci

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// pushChart pushes an artifact shaped like `helm push` output: an OCI manifest with Helm's
// config media type and one chart layer.
func pushChart(t *testing.T, ref string, archive []byte, configType types.MediaType, layers ...[]byte) {
	t.Helper()
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	img = mutate.ConfigMediaType(img, configType)
	if archive != nil {
		layers = append([][]byte{archive}, layers...)
	}
	for _, l := range layers {
		var err error
		img, err = mutate.Append(img, mutate.Addendum{Layer: static.NewLayer(l, HelmChartMediaType)})
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
}

func TestFetchChart(t *testing.T) {
	host := testRegistry(t)
	archive := []byte("\x1f\x8b fake chart archive bytes")
	pushChart(t, host+"/charts/web:1.0.0", archive, HelmConfigMediaType)
	var buf bytes.Buffer
	digest, err := FetchChart(context.Background(), host+"/charts/web:1.0.0", 1<<20, &buf, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), archive) || !strings.HasPrefix(digest, "sha256:") {
		t.Errorf("archive %q, digest %s", buf.Bytes(), digest)
	}

	if _, err := FetchChart(context.Background(), host+"/charts/web:1.0.0", 4, &bytes.Buffer{}, Options{}); !errors.Is(err, ErrLimit) {
		t.Errorf("the declared size is bounded before download: %v", err)
	}
	pushChart(t, host+"/charts/notchart:1.0.0", archive, types.OCIConfigJSON)
	if _, err := FetchChart(context.Background(), host+"/charts/notchart:1.0.0", 1<<20, &bytes.Buffer{}, Options{}); !errors.Is(err, ErrNotChart) {
		t.Errorf("an image config is no chart: %v", err)
	}
	pushChart(t, host+"/charts/two:1.0.0", archive, HelmConfigMediaType, []byte("second"))
	if _, err := FetchChart(context.Background(), host+"/charts/two:1.0.0", 1<<20, &bytes.Buffer{}, Options{}); !errors.Is(err, ErrNotChart) {
		t.Errorf("two chart layers are ambiguous: %v", err)
	}
	img, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := name.ParseReference(host + "/charts/image:1.0.0")
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	if _, err := FetchChart(context.Background(), host+"/charts/image:1.0.0", 1<<20, &bytes.Buffer{}, Options{}); !errors.Is(err, ErrNotChart) {
		t.Errorf("a container image is no chart: %v", err)
	}
}
