package oci

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/nocs90/shieldmon/internal/model"
)

// OCI annotations naming the image an image is built on (image-spec annotations.md).
const (
	AnnotationBaseName   = "org.opencontainers.image.base.name"
	AnnotationBaseDigest = "org.opencontainers.image.base.digest"
)

// maxAnnotationValue bounds the base annotations: they come from whoever built the image.
const maxAnnotationValue = 512

var sha256Digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ImageInfo is what ShieldMon reads of an image without pulling its layers: the manifest and
// the config (docs/adr/0022-base-image-lineage.md).
type ImageInfo struct {
	Resolved
	// Created is the config's creation time (zero when absent); reproducible builds set it to
	// the epoch or the source date.
	Created time.Time
	// DiffIDs are the uncompressed layer digests of the config, base layers first.
	DiffIDs []string
	// BaseName is the base annotation's reference when it is a tag to follow; BaseRepository
	// its repository, and BaseDigest the claimed base digest (from base.digest, or a digest
	// reference in base.name). Set only when present and valid.
	BaseName       string
	BaseRepository string
	BaseDigest     string
	// Problems lists annotation values that were ignored, for the record.
	Problems []string
}

// Inspect resolves ref to the platform image and reads its manifest and config, within the
// limits: no layer is downloaded.
func Inspect(ctx context.Context, ref string, o Options) (ImageInfo, error) {
	r, err := ParseReference(ref, o.Insecure)
	if err != nil {
		return ImageInfo{}, err
	}
	desc, err := remote.Get(r, o.remoteOpts(ctx)...)
	if err != nil {
		return ImageInfo{}, classify(err)
	}
	info := ImageInfo{Resolved: Resolved{
		Input: r.Name(), Repository: r.Context().Name(), Registry: r.Context().RegistryStr(),
		Digest: desc.Digest.String(), MediaType: string(desc.MediaType),
	}}
	var annotations map[string]string
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return ImageInfo{}, classify(err)
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return ImageInfo{}, classify(err)
		}
		chosen := choosePlatform(im, o.Platform)
		if chosen == nil {
			return ImageInfo{}, fmt.Errorf("%s: no manifest for platform %s", r.Name(), o.Platform)
		}
		info.IndexDigest, info.Digest, info.MediaType = desc.Digest.String(), chosen.Digest.String(), string(chosen.MediaType)
		annotations = chosen.Annotations
		r = r.Context().Digest(info.Digest)
	} else if !desc.MediaType.IsImage() {
		return ImageInfo{}, fmt.Errorf("%s: %w (media type %s)", r.Name(), ErrNotImage, desc.MediaType)
	}
	img, err := remote.Image(r, o.remoteOpts(ctx)...)
	if err != nil {
		return ImageInfo{}, classify(err)
	}
	got, err := img.Digest()
	if err != nil {
		return ImageInfo{}, classify(err)
	}
	if got.String() != info.Digest {
		return ImageInfo{}, fmt.Errorf("%s: digest mismatch: requested %s, registry served %s", r.Name(), info.Digest, got)
	}
	if err := checkManifest(img, o.limits()); err != nil {
		return ImageInfo{}, fmt.Errorf("%s: %w", r.Name(), err)
	}
	m, err := img.Manifest()
	if err != nil {
		return ImageInfo{}, classify(err)
	}
	cfg, err := checkedConfig(img, o.limits())
	if err != nil {
		return ImageInfo{}, fmt.Errorf("%s: %w", r.Name(), err)
	}
	info.Platform = model.Platform{OS: cfg.OS, Architecture: cfg.Architecture, Variant: cfg.Variant}
	info.Created = cfg.Created.UTC()
	if len(cfg.RootFS.DiffIDs) > o.limits().MaxLayers {
		return ImageInfo{}, fmt.Errorf("%s: %w: %d diff_ids > %d", r.Name(), ErrLimit, len(cfg.RootFS.DiffIDs), o.limits().MaxLayers)
	}
	for _, d := range cfg.RootFS.DiffIDs {
		info.DiffIDs = append(info.DiffIDs, d.String())
	}
	// The platform manifest's own annotations win over its index descriptor's.
	merged := map[string]string{}
	for k, v := range annotations {
		merged[k] = v
	}
	for k, v := range m.Annotations {
		merged[k] = v
	}
	info.baseAnnotations(merged)
	return info, nil
}

// baseAnnotations validates the base annotations: a bounded image reference (a tag to follow,
// or a digest reference whose digest is a claim) and a sha256 digest.
func (info *ImageInfo) baseAnnotations(a map[string]string) {
	if v, ok := a[AnnotationBaseName]; ok {
		if len(v) > maxAnnotationValue {
			info.Problems = append(info.Problems, fmt.Sprintf("%s: longer than %d bytes", AnnotationBaseName, maxAnnotationValue))
		} else if ref, err := ParseReference(v, false); err != nil {
			info.Problems = append(info.Problems, AnnotationBaseName+": not an image reference")
		} else {
			info.BaseRepository = ref.Context().Name()
			if d, isDigest := ref.(name.Digest); isDigest {
				info.BaseDigest = d.DigestStr()
			} else {
				info.BaseName = ref.Name()
			}
		}
	}
	if v, ok := a[AnnotationBaseDigest]; ok {
		info.BaseDigest = v
	}
	if info.BaseDigest != "" && !sha256Digest.MatchString(info.BaseDigest) {
		info.Problems = append(info.Problems, AnnotationBaseDigest+": not a sha256 digest")
		info.BaseDigest = ""
	}
	if info.BaseRepository == "" {
		info.BaseDigest = "" // a digest without a repository cannot be checked
	}
}

func choosePlatform(im *v1.IndexManifest, p model.Platform) *v1.Descriptor {
	want := v1.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant}
	for i := range im.Manifests {
		m := im.Manifests[i]
		if m.Platform != nil && m.Platform.Satisfies(want) && m.MediaType.IsImage() {
			return &m
		}
	}
	return nil
}
