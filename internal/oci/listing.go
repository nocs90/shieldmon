package oci

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Bounds on everything a registry returns while listing: a hostile registry can answer with
// endless pages, huge bodies or names that are not references (I7).
const (
	listMaxPages     = 100
	listMaxBodyBytes = 4 << 20
	listPageSize     = 100
)

// ListResponse bounds and decodes one listing response, classifying 401/403 as ErrAuth.
// Providers that call a registry's own API use it too.
func ListResponse(resp *http.Response, v any) error {
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: %s", ErrAuth, resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("listing: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, listMaxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(body) > listMaxBodyBytes {
		return fmt.Errorf("%w: listing response larger than %d bytes", ErrLimit, listMaxBodyBytes)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("listing: decode: %w", err)
	}
	return nil
}

// V2Lister lists through the registry v2 API with a keychain: `_catalog` for repositories,
// `tags/list` for tags. It serves registries without an API of their own, and tags everywhere.
type V2Lister struct {
	Keychain  authn.Keychain
	Transport http.RoundTripper // http.DefaultTransport when nil
}

func (l V2Lister) client(ctx context.Context, res authn.Resource, reg name.Registry, scope string) (*http.Client, error) {
	auth, err := l.Keychain.Resolve(res)
	if err != nil {
		return nil, err
	}
	base := l.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	rt, err := transport.NewWithContext(ctx, reg, auth, base, []string{scope})
	if err != nil {
		return nil, classify(err)
	}
	return &http.Client{Transport: rt}, nil
}

// Repositories pages through /v2/_catalog.
func (l V2Lister) Repositories(ctx context.Context, registry, prefix string, limit int) ([]string, error) {
	reg, err := name.NewRegistry(registry)
	if err != nil {
		return nil, err
	}
	c, err := l.client(ctx, reg, reg, "registry:catalog:*")
	if err != nil {
		return nil, err
	}
	var out []string
	last := ""
	for page := 0; page < listMaxPages && len(out) < limit; page++ {
		q := url.Values{"n": {strconv.Itoa(listPageSize)}}
		if last != "" {
			q.Set("last", last)
		}
		u := url.URL{Scheme: reg.Scheme(), Host: reg.RegistryStr(), Path: "/v2/_catalog", RawQuery: q.Encode()}
		var doc struct {
			Repositories []string `json:"repositories"`
		}
		more, err := getJSON(ctx, c, u.String(), &doc)
		if err != nil {
			return nil, err
		}
		for _, r := range doc.Repositories {
			if repo, ok := validRepository(registry, r); ok && strings.HasPrefix(r, prefix) && len(out) < limit {
				out = append(out, repo)
			}
		}
		if !more || len(doc.Repositories) == 0 {
			break
		}
		next := doc.Repositories[len(doc.Repositories)-1]
		if next <= last {
			break // a registry that does not advance would loop forever
		}
		last = next
	}
	return out, nil
}

// Tags pages through /v2/<repo>/tags/list and orders tags by descending version: the v2 API
// does not say when a tag was pushed.
func (l V2Lister) Tags(ctx context.Context, repo name.Repository, limit int) ([]Tag, error) {
	c, err := l.client(ctx, repo, repo.Registry, repo.Scope(transport.PullScope))
	if err != nil {
		return nil, err
	}
	var names []string
	last := ""
	for page := 0; page < listMaxPages; page++ {
		q := url.Values{"n": {strconv.Itoa(listPageSize)}}
		if last != "" {
			q.Set("last", last)
		}
		u := url.URL{Scheme: repo.Scheme(), Host: repo.RegistryStr(), Path: "/v2/" + repo.RepositoryStr() + "/tags/list", RawQuery: q.Encode()}
		var doc struct {
			Tags []string `json:"tags"`
		}
		more, err := getJSON(ctx, c, u.String(), &doc)
		if err != nil {
			return nil, err
		}
		for _, t := range doc.Tags {
			if _, err := name.NewTag(repo.Name()+":"+t, name.StrictValidation); err == nil {
				names = append(names, t)
			}
		}
		if !more || len(doc.Tags) == 0 {
			break
		}
		next := doc.Tags[len(doc.Tags)-1]
		if next <= last {
			break
		}
		last = next
	}
	sort.SliceStable(names, func(i, j int) bool { return versionLess(names[j], names[i]) })
	tags := make([]Tag, 0, min(len(names), limit))
	for _, n := range names {
		if len(tags) == limit {
			break
		}
		tags = append(tags, Tag{Name: n})
	}
	return tags, nil
}

// getJSON fetches one page and reports whether the registry announced another one with a
// Link header (rel="next"), as the distribution spec says; page sizes are the registry's.
func getJSON(ctx context.Context, c *http.Client, u string, v any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return false, classify(err)
	}
	more := strings.Contains(resp.Header.Get("Link"), `rel="next"`)
	return more, ListResponse(resp, v)
}

// repoPathComponent is one component of a repository path in the distribution spec's
// grammar. go-containerregistry checks only the characters, so "team/../x" would pass.
var repoPathComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*$`)

// validRepository returns registry/path when path is a valid repository path.
func validRepository(registry, path string) (string, bool) {
	if path == "" || len(path) > 255 {
		return "", false
	}
	for _, c := range strings.Split(path, "/") {
		if !repoPathComponent.MatchString(c) {
			return "", false
		}
	}
	r, err := name.NewRepository(registry+"/"+path, name.StrictValidation)
	if err != nil {
		return "", false
	}
	return r.Name(), true
}

// versionLess orders tags as versions where both look like one (v1.10 > v1.9); a version
// ranks above a tag that is not one (latest, main: moving tags); otherwise by name. It only
// ranks tags; nothing is inferred from it.
func versionLess(a, b string) bool {
	va, oka := versionParts(a)
	vb, okb := versionParts(b)
	if oka != okb {
		return !oka
	}
	if oka {
		for i := 0; i < len(va) && i < len(vb); i++ {
			if va[i] != vb[i] {
				return va[i] < vb[i]
			}
		}
		if len(va) != len(vb) {
			return len(va) < len(vb)
		}
	}
	return a < b
}

// versionParts parses "v1.2.3" or "1.2" (anything after a "-" or "+" ignored).
func versionParts(s string) ([]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// SortTags orders tags newest first: by push time where known, then by version.
func SortTags(tags []Tag) {
	sort.SliceStable(tags, func(i, j int) bool {
		ti, tj := tags[i].Pushed, tags[j].Pushed
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return versionLess(tags[j].Name, tags[i].Name)
	})
}

// errNoListing is what a provider without listing returns, wrapped with its name.
func errNoListing(provider string) error {
	return fmt.Errorf("%s: %w", provider, ErrListingUnsupported)
}
