//go:build integration

package engine_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nocs90/shieldmon/internal/engine"
	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/scanner"
	"github.com/nocs90/shieldmon/internal/store"
)

// The hostile fixture suite (#10, docs/adr/0011-scanner-sandbox.md): images built here, served
// by an in-memory registry and scanned by the real fetcher and scanners under the default
// sandbox. Each case must end bounded, with the expected error and health finding, and
// never touch the host outside the data dir. No binaries are kept in git.

var linuxAMD64 = model.Platform{OS: "linux", Architecture: "amd64"}

// defaultSandbox is what `auto` selects. Where no backend runs (macOS) the cases run
// unconfined, unless SHIELDMON_TEST_SANDBOX is set, as in CI, which makes that a failure.
func defaultSandbox(t *testing.T) scanner.Sandbox {
	t.Helper()
	name, sb, err := scanner.SelectSandbox(scanner.AutoSandbox)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Command(scanner.Policy{}, "/bin/true", nil); err != nil {
		if os.Getenv("SHIELDMON_TEST_SANDBOX") != "" {
			t.Fatalf("the default sandbox must run here: %v", err)
		}
		t.Logf("no sandbox backend here, running unconfined: %v", err)
		_, sb, _ = scanner.SelectSandbox("none")
		return sb
	}
	t.Logf("sandbox: %s", name)
	return sb
}

type hostile struct {
	t     *testing.T
	ctx   context.Context
	reg   string
	store *store.Store
	eng   *engine.Engine
	data  string
}

// newHostile builds an engine like the CLI does: real fetcher with limits, real scanners
// (matchers in matchers, generators they imply) in the default sandbox, data dir caches and
// scratch space. specs overrides scanner binaries.
func newHostile(t *testing.T, limits oci.Limits, run scanner.Runner, matchers []string, specs map[string]scanner.Spec) *hostile {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	st, err := store.Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	data := t.TempDir()
	sb := defaultSandbox(t)
	run.Sandbox = sb
	run.CacheDir, run.TempDir = filepath.Join(data, "cache"), filepath.Join(data, "tmp")
	for k, s := range specs {
		s.Runner = run
		specs[k] = s
	}
	set, err := scanner.Build(matchers, specs, run)
	if err != nil {
		t.Fatal(err)
	}
	return &hostile{
		t: t, ctx: ctx, reg: strings.TrimPrefix(srv.URL, "http://"), store: st, data: data,
		eng: &engine.Engine{
			Store: st, Scanners: set, DataDir: data,
			Fetcher:   engine.RegistryFetcher{Options: oci.Options{Insecure: true, Limits: limits}},
			Sandboxed: scanner.Confined(sb), SandboxDegraded: scanner.SandboxDegraded(sb),
		},
	}
}

// push publishes layers as a linux/amd64 image and returns its reference.
func (h *hostile) push(repo string, layers ...v1.Layer) string {
	h.t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		h.t.Fatal(err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		h.t.Fatal(err)
	}
	cfg = cfg.DeepCopy()
	cfg.OS, cfg.Architecture = "linux", "amd64"
	if img, err = mutate.ConfigFile(img, cfg); err != nil {
		h.t.Fatal(err)
	}
	ref := h.reg + "/" + repo + ":1"
	r, err := name.ParseReference(ref, name.Insecure)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := remote.Write(r, img, remote.WithContext(h.ctx)); err != nil {
		h.t.Fatal(err)
	}
	return ref
}

// scan scans ref and returns the result; a resolve failure is a test failure.
func (h *hostile) scan(ref string) engine.Result {
	h.t.Helper()
	r, err := h.eng.Scan(h.ctx, ref, linuxAMD64)
	if err != nil {
		h.t.Fatalf("scan %s: %v", ref, err)
	}
	return r
}

// openHealth returns the open health finding for check and subject, failing if there is none.
func (h *hostile) openHealth(check, subject string) store.HealthFinding {
	h.t.Helper()
	hs, err := h.store.ListHealth(h.ctx, true)
	if err != nil {
		h.t.Fatal(err)
	}
	for _, hf := range hs {
		if hf.Check == check && hf.Subject == subject && hf.State == "open" {
			return hf
		}
	}
	h.t.Fatalf("no open %s health finding for %s; have %+v", check, subject, hs)
	return store.HealthFinding{}
}

// scratchIsClean checks that nothing a scan wrote is left under the data dir's tmp.
func (h *hostile) scratchIsClean() {
	h.t.Helper()
	entries, err := os.ReadDir(filepath.Join(h.data, "tmp"))
	if err != nil && !os.IsNotExist(err) {
		h.t.Fatal(err)
	}
	if len(entries) > 0 {
		h.t.Errorf("scan left %d entries in the scratch space", len(entries))
	}
}

// tarLayer is an uncompressed tar layer built by write.
func tarLayer(t *testing.T, write func(*tar.Writer) error) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := write(tw); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func defaultLimits() oci.Limits { return oci.DefaultLimits }

// rawManifest is pushed as is: a hostile registry serves whatever manifest it likes.
type rawManifest []byte

func (m rawManifest) RawManifest() ([]byte, error)        { return m, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return types.DockerManifestSchema2, nil }

// pushManyLayers publishes a manifest that lists one tiny layer n times, with a matching
// config: the manifest is what is hostile, not the bytes.
func (h *hostile) pushManyLayers(repo string, n int) string {
	h.t.Helper()
	r, err := name.NewRepository(h.reg+"/"+repo, name.Insecure)
	if err != nil {
		h.t.Fatal(err)
	}
	layer := tarLayer(h.t, func(tw *tar.Writer) error {
		return tw.WriteHeader(&tar.Header{Name: "empty", Mode: 0o644, Typeflag: tar.TypeReg})
	})
	desc, err := partialDescriptor(layer)
	if err != nil {
		h.t.Fatal(err)
	}
	diffID, err := layer.DiffID()
	if err != nil {
		h.t.Fatal(err)
	}
	cfg := v1.ConfigFile{OS: "linux", Architecture: "amd64", RootFS: v1.RootFS{Type: "layers"}}
	m := v1.Manifest{SchemaVersion: 2, MediaType: types.DockerManifestSchema2}
	for range n {
		cfg.RootFS.DiffIDs = append(cfg.RootFS.DiffIDs, diffID)
		m.Layers = append(m.Layers, desc)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	cfgBlob := static.NewLayer(cfgJSON, types.DockerConfigJSON)
	if m.Config, err = partialDescriptor(cfgBlob); err != nil {
		h.t.Fatal(err)
	}
	for _, blob := range []v1.Layer{layer, cfgBlob} {
		if err := remote.WriteLayer(r, blob, remote.WithContext(h.ctx)); err != nil {
			h.t.Fatal(err)
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		h.t.Fatal(err)
	}
	ref := r.Tag("1")
	if err := remote.Put(ref, rawManifest(raw), remote.WithContext(h.ctx)); err != nil {
		h.t.Fatal(err)
	}
	return ref.String()
}

func partialDescriptor(l v1.Layer) (v1.Descriptor, error) {
	d, err := partial.Descriptor(l)
	if err != nil {
		return v1.Descriptor{}, err
	}
	return *d, nil
}

func TestHostileManyLayers(t *testing.T) {
	h := newHostile(t, defaultLimits(), scanner.Runner{Timeout: time.Minute}, []string{"grype"}, nil)
	r := h.scan(h.pushManyLayers("many-layers", 10000))
	if r.Status != store.ScanFailed || len(r.SBOMsCreated) != 0 {
		t.Fatalf("a 10,000-layer image must not be cataloged: %+v", r)
	}
	if hf := h.openHealth(engine.CheckFetch, h.reg); !strings.Contains(hf.Detail, "layers") {
		t.Errorf("fetch_failed must name the layer limit: %s", hf.Detail)
	}
	h.scratchIsClean()
}

func TestHostileGiantLayer(t *testing.T) {
	limits := defaultLimits()
	limits.MaxLayerBytes = 1 << 20
	h := newHostile(t, limits, scanner.Runner{Timeout: time.Minute}, []string{"grype"}, nil)
	layer, err := random.Layer(2<<20, types.DockerLayer)
	if err != nil {
		t.Fatal(err)
	}
	r := h.scan(h.push("giant-layer", layer))
	if r.Status != store.ScanFailed || len(r.SBOMsCreated) != 0 {
		t.Fatalf("a layer over the limit must not be downloaded: %+v", r)
	}
	if hf := h.openHealth(engine.CheckFetch, h.reg); !strings.Contains(hf.Detail, "size") {
		t.Errorf("fetch_failed must name the size limit: %s", hf.Detail)
	}
	h.scratchIsClean()
}

func TestHostileDecompressionBomb(t *testing.T) {
	// 1 GiB of zeros is about 1 MiB compressed: well inside every download limit.
	var gz bytes.Buffer
	zw, err := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	const size = 1 << 30
	if err := tw.WriteHeader(&tar.Header{Name: "var/bomb", Mode: 0o644, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	for range size / len(chunk) {
		if _, err := tw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	b := gz.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}

	const quota = 64 << 20
	h := newHostile(t, defaultLimits(), scanner.Runner{Timeout: 5 * time.Minute, ScratchQuota: quota}, []string{"grype", "trivy"}, nil)
	start := time.Now()
	r := h.scan(h.push("bomb", layer))
	t.Logf("bomb scan: %s, status %s, SBOMs %v, errors %q", time.Since(start).Round(time.Second), r.Status, r.SBOMsCreated, r.Errors)
	// Whatever a generator does with the bomb, it must not unpack it past the quota: it
	// either catalogs without unpacking, or is stopped with a health finding.
	for _, gen := range []string{"syft", "trivy"} {
		created := false
		for _, c := range r.SBOMsCreated {
			created = created || c == gen
		}
		if created {
			continue
		}
		hf := h.openHealth(engine.CheckGenerator, gen)
		if !strings.Contains(hf.Detail, "quota") && !strings.Contains(hf.Detail, "file size limit") {
			t.Errorf("%s failed on the bomb for another reason than its bounds: %s", gen, hf.Detail)
		}
	}
	h.scratchIsClean()
}

func TestHostilePathEscapes(t *testing.T) {
	host := t.TempDir() // stands for the rest of the host
	layer := tarLayer(t, func(tw *tar.Writer) error {
		climb := strings.Repeat("../", 32) + strings.TrimPrefix(host, "/")
		for _, h := range []*tar.Header{
			{Name: climb + "/traversal", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4},
			{Name: host + "/absolute", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4},
			{Name: "link", Typeflag: tar.TypeSymlink, Linkname: host, Mode: 0o777},
			{Name: "link/through-symlink", Typeflag: tar.TypeReg, Mode: 0o644, Size: 4},
			{Name: "etc/os-release", Typeflag: tar.TypeSymlink, Linkname: "/etc/os-release", Mode: 0o777},
		} {
			if err := tw.WriteHeader(h); err != nil {
				return err
			}
			if h.Size > 0 {
				if _, err := tw.Write([]byte("pwnd")); err != nil {
					return err
				}
			}
		}
		return nil
	})
	h := newHostile(t, defaultLimits(), scanner.Runner{Timeout: 5 * time.Minute}, []string{"grype", "trivy"}, nil)
	r := h.scan(h.push("escapes", layer))
	t.Logf("escape scan: status %s, SBOMs %v, errors %q", r.Status, r.SBOMsCreated, r.Errors)
	entries, err := os.ReadDir(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("a layer wrote %s outside the image", filepath.Join(host, e.Name()))
	}
	h.scratchIsClean()
}

func TestHostileHangingScanner(t *testing.T) {
	// A generator that never exits, not even for `version`.
	hang := filepath.Join(t.TempDir(), "syft")
	if err := os.WriteFile(hang, []byte("#!/bin/sh\nsleep 600\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	specs := map[string]scanner.Spec{"syft": {Bin: scanner.Binary{Name: "syft", Path: hang}}}
	h := newHostile(t, defaultLimits(), scanner.Runner{Timeout: 3 * time.Second}, []string{"grype"}, specs)
	layer := tarLayer(t, func(tw *tar.Writer) error {
		return tw.WriteHeader(&tar.Header{Name: "empty", Mode: 0o644, Typeflag: tar.TypeReg})
	})
	start := time.Now()
	r := h.scan(h.push("hang", layer))
	if elapsed := time.Since(start); elapsed > time.Minute {
		t.Errorf("a hanging scanner held the scan for %s (timeout 3s)", elapsed.Round(time.Second))
	}
	if len(r.SBOMsCreated) != 0 {
		t.Fatalf("a hanging generator cannot produce an SBOM: %+v", r)
	}
	if hf := h.openHealth(engine.CheckGenerator, "syft"); !strings.Contains(hf.Detail, "timed out") {
		t.Errorf("sbom_generator_failed must say the scanner timed out: %s", hf.Detail)
	}
	h.scratchIsClean()
}
