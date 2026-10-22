// Package oci resolves image references to immutable digests and fetches
// images into a local OCI layout without a Docker daemon. Registry
// responses and image content are treated as hostile input: sizes are
// bounded before download and blobs are digest-verified while reading.
package oci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nocs90/shieldmon/internal/model"
)

// ErrAuth wraps registry authentication/authorization failures.
var ErrAuth = errors.New("registry authentication failed")

// ErrLimit is returned when an image exceeds configured limits.
var ErrLimit = errors.New("image exceeds limits")

// ErrNotImage is returned for OCI artifacts that are not container images.
var ErrNotImage = errors.New("artifact is not a container image")

// Limits bound what ShieldMon is willing to download.
type Limits struct {
	MaxLayers      int
	MaxLayerBytes  int64
	MaxTotalBytes  int64
	MaxConfigBytes int64
}

// DefaultLimits are generous for real-world images and stop obvious abuse.
var DefaultLimits = Limits{
	MaxLayers:      256,
	MaxLayerBytes:  4 << 30,
	MaxTotalBytes:  16 << 30,
	MaxConfigBytes: 4 << 20,
}

// Options configure registry access.
type Options struct {
	Platform  model.Platform
	Keychain  authn.Keychain
	Transport http.RoundTripper
	// Insecure allows plain-HTTP registries. Only for tests and local labs.
	Insecure  bool
	Limits    Limits
	UserAgent string
}

func (o Options) remoteOpts(ctx context.Context) []remote.Option {
	kc := o.Keychain
	if kc == nil {
		kc = Keychain()
	}
	opts := []remote.Option{remote.WithContext(ctx), remote.WithAuthFromKeychain(kc)}
	if o.Transport != nil {
		opts = append(opts, remote.WithTransport(o.Transport))
	}
	if o.UserAgent != "" {
		opts = append(opts, remote.WithUserAgent(o.UserAgent))
	}
	return opts
}

func (o Options) limits() Limits {
	if o.Limits == (Limits{}) {
		return DefaultLimits
	}
	return o.Limits
}

// Resolved is the immutable identity of what will be scanned.
type Resolved struct {
	// Input is the reference as normalized from user input (tag or digest).
	Input string
	// Repository is the fully-qualified repository, e.g. index.docker.io/library/alpine.
	Repository string
	// Registry is the registry host.
	Registry string
	// Digest is the platform-specific image manifest digest: the identity.
	Digest string
	// IndexDigest is set when Input pointed to a multi-platform index.
	IndexDigest string
	MediaType   string
	Platform    model.Platform
}

// DigestRef returns repository@digest.
func (r Resolved) DigestRef() string { return r.Repository + "@" + r.Digest }

// ParseReference validates an image reference.
func ParseReference(ref string, insecure bool) (name.Reference, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, " \t\r\n") || strings.HasPrefix(ref, "-") {
		return nil, fmt.Errorf("invalid image reference %q", ref)
	}
	var opts []name.Option
	if insecure {
		opts = append(opts, name.Insecure)
	}
	r, err := name.ParseReference(ref, opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	return r, nil
}

// Resolve turns a tag or digest reference into a platform manifest digest.
func Resolve(ctx context.Context, ref string, o Options) (Resolved, error) {
	r, err := ParseReference(ref, o.Insecure)
	if err != nil {
		return Resolved{}, err
	}
	desc, err := remote.Get(r, o.remoteOpts(ctx)...)
	if err != nil {
		return Resolved{}, classify(err)
	}
	res := Resolved{
		Input:      r.Name(),
		Repository: r.Context().Name(),
		Registry:   r.Context().RegistryStr(),
		Digest:     desc.Digest.String(),
		MediaType:  string(desc.MediaType),
	}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return Resolved{}, classify(err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return Resolved{}, classify(err)
		}
		want := v1.Platform{OS: o.Platform.OS, Architecture: o.Platform.Architecture, Variant: o.Platform.Variant}
		var chosen *v1.Descriptor
		for i := range im.Manifests {
			m := im.Manifests[i]
			if m.Platform != nil && m.Platform.Satisfies(want) && m.MediaType.IsImage() {
				chosen = &m
				break
			}
		}
		if chosen == nil {
			return Resolved{}, fmt.Errorf("%s: no manifest for platform %s", r.Name(), o.Platform)
		}
		res.IndexDigest = desc.Digest.String()
		res.Digest = chosen.Digest.String()
		res.MediaType = string(chosen.MediaType)
		res.Platform = model.Platform{OS: chosen.Platform.OS, Architecture: chosen.Platform.Architecture, Variant: chosen.Platform.Variant}
		return res, nil
	}
	if !desc.MediaType.IsImage() {
		return Resolved{}, fmt.Errorf("%s: %w (media type %s)", r.Name(), ErrNotImage, desc.MediaType)
	}
	img, err := desc.Image()
	if err != nil {
		return Resolved{}, classify(err)
	}
	cfg, err := checkedConfig(img, o.limits())
	if err != nil {
		return Resolved{}, fmt.Errorf("%s: %w", r.Name(), err)
	}
	res.Platform = model.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
	return res, nil
}

// Fetch downloads repository@digest into an OCI layout at dir after checking
// the manifest against limits. Blobs are verified against their digests by
// go-containerregistry while streaming.
func Fetch(ctx context.Context, r Resolved, dir string, o Options) error {
	ref, err := ParseReference(r.DigestRef(), o.Insecure)
	if err != nil {
		return err
	}
	if _, ok := ref.(name.Digest); !ok {
		return fmt.Errorf("fetch requires a digest reference, got %s", ref)
	}
	img, err := remote.Image(ref, o.remoteOpts(ctx)...)
	if err != nil {
		return classify(err)
	}
	if err := checkManifest(img, o.limits()); err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	if _, err := checkedConfig(img, o.limits()); err != nil {
		return fmt.Errorf("%s: %w", ref, err)
	}
	got, err := img.Digest()
	if err != nil {
		return err
	}
	if got.String() != r.Digest {
		return fmt.Errorf("digest mismatch: requested %s, registry served %s", r.Digest, got)
	}
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	if err := p.AppendImage(img); err != nil {
		return classify(err)
	}
	return nil
}

func checkManifest(img v1.Image, l Limits) error {
	m, err := img.Manifest()
	if err != nil {
		return classify(err)
	}
	if len(m.Layers) > l.MaxLayers {
		return fmt.Errorf("%w: %d layers > %d", ErrLimit, len(m.Layers), l.MaxLayers)
	}
	var total int64
	for _, layer := range m.Layers {
		if layer.Size < 0 || layer.Size > l.MaxLayerBytes {
			return fmt.Errorf("%w: layer %s size %d > %d", ErrLimit, layer.Digest, layer.Size, l.MaxLayerBytes)
		}
		total += layer.Size
	}
	if total > l.MaxTotalBytes {
		return fmt.Errorf("%w: total size %d > %d", ErrLimit, total, l.MaxTotalBytes)
	}
	if m.Config.Size > l.MaxConfigBytes {
		return fmt.Errorf("%w: config size %d > %d", ErrLimit, m.Config.Size, l.MaxConfigBytes)
	}
	return nil
}

var imageConfigTypes = map[types.MediaType]bool{
	types.DockerConfigJSON: true,
	types.OCIConfigJSON:    true,
}

func checkedConfig(img v1.Image, l Limits) (*v1.ConfigFile, error) {
	m, err := img.Manifest()
	if err != nil {
		return nil, classify(err)
	}
	if !imageConfigTypes[m.Config.MediaType] {
		return nil, fmt.Errorf("%w: config media type %s", ErrNotImage, m.Config.MediaType)
	}
	if m.Config.Size > l.MaxConfigBytes {
		return nil, fmt.Errorf("%w: config size %d > %d", ErrLimit, m.Config.Size, l.MaxConfigBytes)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, classify(err)
	}
	return cfg, nil
}

func classify(err error) error {
	var terr *transport.Error
	if errors.As(err, &terr) && (terr.StatusCode == http.StatusUnauthorized || terr.StatusCode == http.StatusForbidden) {
		return fmt.Errorf("%w: %w", ErrAuth, err)
	}
	return err
}
