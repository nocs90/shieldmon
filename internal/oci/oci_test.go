package oci

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nocs90/shieldmon/internal/model"
)

func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func push(t *testing.T, ref string, img v1.Image) v1.Hash {
	t.Helper()
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(r, img); err != nil {
		t.Fatal(err)
	}
	d, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func withPlatform(t *testing.T, img v1.Image, os, arch string) v1.Image {
	t.Helper()
	cfg, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = os, arch
	img, err = mutate.ConfigFile(img, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

var amd64 = model.Platform{OS: "linux", Architecture: "amd64"}

func opts() Options { return Options{Insecure: true, Platform: amd64} }

func TestResolveTagToDigest(t *testing.T) {
	reg := testRegistry(t)
	img, _ := random.Image(1024, 2)
	img = withPlatform(t, img, "linux", "amd64")
	want := push(t, reg+"/app:1.0", img)

	r, err := Resolve(context.Background(), reg+"/app:1.0", opts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Digest != want.String() || r.IndexDigest != "" {
		t.Errorf("resolved %+v, want digest %s", r, want)
	}
	if r.Platform != amd64 || r.Repository != reg+"/app" || r.Registry != reg {
		t.Errorf("resolved %+v", r)
	}
	if r.DigestRef() != reg+"/app@"+want.String() {
		t.Errorf("digest ref = %s", r.DigestRef())
	}
}

func TestResolveIndexPicksPlatform(t *testing.T) {
	reg := testRegistry(t)
	a, _ := random.Image(512, 1)
	b, _ := random.Image(512, 1)
	a = withPlatform(t, a, "linux", "amd64")
	b = withPlatform(t, b, "linux", "arm64")
	idx := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: a, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}}},
		mutate.IndexAddendum{Add: b, Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}}},
	)
	ref, _ := name.ParseReference(reg+"/multi:latest", name.Insecure)
	if err := remote.WriteIndex(ref, idx); err != nil {
		t.Fatal(err)
	}
	idxDigest, _ := idx.Digest()
	bDigest, _ := b.Digest()

	o := opts()
	o.Platform = model.Platform{OS: "linux", Architecture: "arm64"}
	r, err := Resolve(context.Background(), reg+"/multi:latest", o)
	if err != nil {
		t.Fatal(err)
	}
	if r.Digest != bDigest.String() || r.IndexDigest != idxDigest.String() {
		t.Errorf("want arm64 manifest %s under index %s, got %+v", bDigest, idxDigest, r)
	}

	o.Platform = model.Platform{OS: "linux", Architecture: "s390x"}
	if _, err := Resolve(context.Background(), reg+"/multi:latest", o); err == nil {
		t.Error("missing platform must be an error")
	}
}

func TestFetchWritesVerifiedLayout(t *testing.T) {
	reg := testRegistry(t)
	img, _ := random.Image(2048, 3)
	img = withPlatform(t, img, "linux", "amd64")
	push(t, reg+"/app:1.0", img)
	r, err := Resolve(context.Background(), reg+"/app:1.0", opts())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "oci")
	if err := Fetch(context.Background(), r, dir, opts()); err != nil {
		t.Fatal(err)
	}
	p, err := layout.FromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := v1.NewHash(r.Digest)
	got, err := p.Image(h)
	if err != nil {
		t.Fatalf("image %s not in layout: %v", r.Digest, err)
	}
	layers, _ := got.Layers()
	if len(layers) != 3 {
		t.Errorf("layers = %d, want 3", len(layers))
	}
	if _, err := os.Stat(filepath.Join(dir, "oci-layout")); err != nil {
		t.Error("not an OCI layout")
	}
}

func TestFetchEnforcesLimits(t *testing.T) {
	reg := testRegistry(t)
	img, _ := random.Image(4096, 3)
	img = withPlatform(t, img, "linux", "amd64")
	push(t, reg+"/big:1", img)
	r, err := Resolve(context.Background(), reg+"/big:1", opts())
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Limits{
		"layer count": {MaxLayers: 2, MaxLayerBytes: 1 << 20, MaxTotalBytes: 1 << 20, MaxConfigBytes: 1 << 20},
		"layer size":  {MaxLayers: 10, MaxLayerBytes: 100, MaxTotalBytes: 1 << 20, MaxConfigBytes: 1 << 20},
		"total size":  {MaxLayers: 10, MaxLayerBytes: 1 << 20, MaxTotalBytes: 1000, MaxConfigBytes: 1 << 20},
	} {
		o := opts()
		o.Limits = l
		err := Fetch(context.Background(), r, filepath.Join(t.TempDir(), "oci"), o)
		if !errors.Is(err, ErrLimit) {
			t.Errorf("%s: want ErrLimit, got %v", name, err)
		}
	}
}

func TestRejectsNonImageArtifacts(t *testing.T) {
	reg := testRegistry(t)
	img, _ := random.Image(256, 1)
	// A Helm chart pushed to an OCI registry: same manifest shape, chart config type.
	chart := mutate.ConfigMediaType(img, types.MediaType("application/vnd.cncf.helm.config.v1+json"))
	push(t, reg+"/charts/app:1.0.0", chart)
	_, err := Resolve(context.Background(), reg+"/charts/app:1.0.0", opts())
	if !errors.Is(err, ErrNotImage) {
		t.Fatalf("want ErrNotImage, got %v", err)
	}
}

func TestAuthFailuresAreClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	reg := strings.TrimPrefix(srv.URL, "http://")
	_, err := Resolve(context.Background(), reg+"/private:1", opts())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestParseReferenceRejectsInjection(t *testing.T) {
	for _, ref := range []string{"", "-o=/etc/passwd", "alpine latest", "alpine\n:latest", "UPPER/Case:1"} {
		if _, err := ParseReference(ref, false); err == nil {
			t.Errorf("ParseReference(%q) must fail", ref)
		}
	}
}

func TestKeychainIsAnonymousForUnknownRegistries(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // no docker login
	reg, err := name.NewRegistry("registry.example.test")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := Keychain().Resolve(reg)
	if err != nil {
		t.Fatal(err)
	}
	if auth != authn.Anonymous {
		t.Errorf("unknown registry must resolve to anonymous, got %T", auth)
	}
}
