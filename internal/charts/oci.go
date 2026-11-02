package charts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

func init() {
	Register(Plugin{
		Name:        "oci",
		Description: "Helm charts in an OCI registry (oci://), with the registries' credentials",
		Options:     []string{"repository"},
		New: func(s Spec) (Source, error) {
			repo, err := s.Options.String("repository", "")
			if err != nil {
				return nil, err
			}
			repo = strings.TrimSuffix(strings.TrimPrefix(repo, "oci://"), "/")
			if !ociRepository.MatchString(repo) {
				return nil, errors.New("option repository: want a registry path, e.g. ghcr.io/org/charts")
			}
			if s.Derived && !publicHost(strings.SplitN(repo, "/", 2)[0]) {
				return nil, fmt.Errorf("repository %q: %w", truncate(repo), ErrNotPublic)
			}
			if s.OCI == nil {
				return nil, errors.New("oci chart source: no registry access configured")
			}
			return &ociSource{repo: repo, oci: s.OCI}, nil
		},
	})
}

// ociRepository is host[:port]/path, lowercase as registries require.
var ociRepository = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$`)

// chartName is a Helm chart name: also a repository path component in a registry.
var chartName = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,99})$`)

type ociSource struct {
	repo string
	oci  OCI
}

func (o *ociSource) Location(chart string) string { return "oci://" + o.repo + "/" + chart }

func (o *ociSource) ref(chart string) (string, error) {
	if !chartName.MatchString(chart) {
		return "", fmt.Errorf("chart %q: not a chart name", truncate(chart))
	}
	return o.repo + "/" + chart, nil
}

func (o *ociSource) Versions(ctx context.Context, chart string) ([]Version, error) {
	repo, err := o.ref(chart)
	if err != nil {
		return nil, err
	}
	// Registries list tags in their own order (often lexical): ask for many, keep the newest.
	tags, err := o.oci.Tags(ctx, repo, maxOCITags)
	if err != nil {
		return nil, err
	}
	if len(tags) >= maxOCITags {
		return nil, fmt.Errorf("%s: %d tags or more: the newest versions may be past what is listed", repo, maxOCITags)
	}
	var out []Version
	for _, t := range tags {
		// Helm stores "+" (build metadata) as "_" in tags.
		if v := strings.Replace(t, "_", "+", 1); validVersion(v) {
			out = append(out, Version{Version: v})
		}
	}
	sortByVersion(out, func(v Version) string { return v.Version })
	return out[:min(len(out), MaxVersions)], nil
}

// maxOCITags bounds the tags listed for one chart repository.
const maxOCITags = 10_000

func (o *ociSource) Fetch(ctx context.Context, chart, version string, w io.Writer) (string, error) {
	repo, err := o.ref(chart)
	if err != nil {
		return "", err
	}
	if !validVersion(version) {
		return "", fmt.Errorf("version %q: not a chart version", truncate(version))
	}
	return o.oci.Fetch(ctx, repo+":"+strings.Replace(version, "+", "_", 1), MaxArchiveBytes, w)
}
