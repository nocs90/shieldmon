package charts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// ArtifactHubURL is Artifact Hub's API.
const ArtifactHubURL = "https://artifacthub.io/api/v1"

func init() {
	Register(Plugin{
		Name:        "artifacthub",
		Description: "a chart found on Artifact Hub, fetched from the repository Artifact Hub names (HTTP or OCI)",
		Options:     []string{"repository", "url"},
		New: func(s Spec) (Source, error) {
			repo, err := s.Options.String("repository", "")
			if err != nil {
				return nil, err
			}
			if !ahName.MatchString(repo) {
				return nil, errors.New("option repository: want the Artifact Hub repository name, e.g. ingress-nginx")
			}
			raw, err := s.Options.String("url", ArtifactHubURL)
			if err != nil {
				return nil, err
			}
			api, err := parseURL("url", raw)
			if err != nil {
				return nil, err
			}
			return &ahSource{api: api, repo: repo, spec: s}, nil
		},
	})
}

var ahName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

// ahSource asks Artifact Hub where the chart lives, once, then reads it from there: the
// versions and archives come from the chart's own repository, never from Artifact Hub.
type ahSource struct {
	api  *url.URL
	repo string
	spec Spec

	mu       sync.Mutex
	resolved map[string]Source
	location map[string]string
}

func (a *ahSource) Location(chart string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if l, ok := a.location[chart]; ok {
		return l
	}
	return "artifacthub:" + a.repo + "/" + chart
}

// maxPackageBytes bounds an Artifact Hub package answer (it carries the README).
const maxPackageBytes = 8 << 20

func (a *ahSource) source(ctx context.Context, chart string) (Source, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.resolved[chart]; ok {
		return s, nil
	}
	if !chartName.MatchString(chart) {
		return nil, fmt.Errorf("chart %q: not a chart name", truncate(chart))
	}
	u := a.api.JoinPath("packages", "helm", a.repo, chart)
	data, err := get(ctx, a.spec.Client, u, maxPackageBytes, nil)
	if err != nil {
		return nil, err
	}
	var pkg struct {
		Repository struct {
			URL string `json:"url"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("%s: package: %w", u.Host, err)
	}
	// The repository comes from Artifact Hub's answer: reached as remote content, https and
	// public addresses only (Derived).
	var s Source
	loc := pkg.Repository.URL
	spec := Spec{Client: a.spec.Client, Public: a.spec.Public, OCI: a.spec.OCI, Derived: true}
	if repo, isOCI := strings.CutPrefix(loc, "oci://"); isOCI {
		// The source takes the parent of the chart's repository; Artifact Hub may name either.
		spec.Options = Options{"repository": strings.TrimSuffix(strings.TrimSuffix(repo, "/"), "/"+chart)}
		s, err = New("oci", spec)
	} else {
		spec.Options = Options{"url": loc}
		s, err = New("http", spec)
	}
	if err != nil {
		return nil, fmt.Errorf("artifacthub %s/%s: repository %q: %w", a.repo, truncate(chart), truncate(loc), err)
	}
	if a.resolved == nil {
		a.resolved, a.location = map[string]Source{}, map[string]string{}
	}
	a.resolved[chart], a.location[chart] = s, s.Location(chart)
	return s, nil
}

func (a *ahSource) Versions(ctx context.Context, chart string) ([]Version, error) {
	s, err := a.source(ctx, chart)
	if err != nil {
		return nil, err
	}
	return s.Versions(ctx, chart)
}

func (a *ahSource) Fetch(ctx context.Context, chart, version string, w io.Writer) (string, error) {
	s, err := a.source(ctx, chart)
	if err != nil {
		return "", err
	}
	return s.Fetch(ctx, chart, version, w)
}
