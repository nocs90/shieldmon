package oci

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Media types of a Helm chart stored in an OCI registry (Helm's OCI support).
const (
	HelmConfigMediaType = "application/vnd.cncf.helm.config.v1+json"
	HelmChartMediaType  = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
)

// ErrNotChart is returned for OCI artifacts that are not Helm charts.
var ErrNotChart = errors.New("artifact is not a Helm chart")

// FetchChart writes the chart archive of ref (repository:version or @digest) to w, at most
// maxBytes, and returns the manifest digest: the chart version's identity. Registry
// credentials are used here only, like for images; the archive is verified against its
// digest while streaming.
func FetchChart(ctx context.Context, ref string, maxBytes int64, w io.Writer, o Options) (string, error) {
	r, err := ParseReference(ref, o.Insecure)
	if err != nil {
		return "", err
	}
	desc, err := remote.Get(r, o.remoteOpts(ctx)...)
	if err != nil {
		return "", classify(err)
	}
	if desc.MediaType != types.OCIManifestSchema1 {
		return "", fmt.Errorf("%s: %w (media type %q)", r.Name(), ErrNotChart, desc.MediaType)
	}
	img, err := desc.Image()
	if err != nil {
		return "", classify(err)
	}
	m, err := img.Manifest()
	if err != nil {
		return "", classify(err)
	}
	if m.Config.MediaType != HelmConfigMediaType {
		return "", fmt.Errorf("%s: %w (config media type %q)", r.Name(), ErrNotChart, m.Config.MediaType)
	}
	var found bool
	for _, l := range m.Layers {
		if l.MediaType != HelmChartMediaType {
			continue
		}
		if found {
			return "", fmt.Errorf("%s: %w: more than one chart layer", r.Name(), ErrNotChart)
		}
		found = true
		if l.Size < 0 || l.Size > maxBytes {
			return "", fmt.Errorf("%s: %w: chart of %d bytes > %d", r.Name(), ErrLimit, l.Size, maxBytes)
		}
		layer, err := img.LayerByDigest(l.Digest)
		if err != nil {
			return "", classify(err)
		}
		rc, err := layer.Compressed() // the blob as stored, verified against its digest
		if err != nil {
			return "", classify(err)
		}
		n, err := io.Copy(w, io.LimitReader(rc, maxBytes+1))
		closeErr := rc.Close()
		if err != nil {
			return "", classify(err)
		}
		if closeErr != nil {
			return "", classify(closeErr)
		}
		if n > maxBytes {
			return "", fmt.Errorf("%s: %w: chart larger than %d bytes", r.Name(), ErrLimit, maxBytes)
		}
	}
	if !found {
		return "", fmt.Errorf("%s: %w: no chart layer", r.Name(), ErrNotChart)
	}
	return desc.Digest.String(), nil
}
