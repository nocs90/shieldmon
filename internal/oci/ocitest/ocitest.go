// Package ocitest is the conformance kit for registry providers (docs/extending/
// registry-provider.md). A provider's test wires the provider to a fake backend and calls
// CheckProvider; FakeRegistry is a v2 registry for providers that list through it.
package ocitest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/oci"
)

// Fixture is a provider wired by its test to a fake backend.
type Fixture struct {
	// Name is the provider's registered name.
	Name string
	// Provider is the instance under test; its backend accepts its credentials.
	Provider oci.Provider
	// Denied is the same provider against a backend that rejects its credentials (401),
	// serving DeniedRegistry.
	Denied         oci.Provider
	DeniedRegistry string
	// Registry is a registry the provider owns and the fake serves.
	Registry string
	// Repositories is how many repositories the fake holds (more than 3), or 0 when the
	// provider does not list repositories.
	Repositories int
	// Repo is a repository on the fake with at least 5 tags.
	Repo string
	// Secret is a credential the provider was given: no error may contain it.
	Secret string
}

// CheckProvider verifies a provider's contract: registration, what it owns, bounded and
// valid listings, cancellation, authentication failures classified and redacted.
func CheckProvider(t *testing.T, f Fixture) {
	t.Helper()
	p, ok := oci.LookupProvider(f.Name)
	if !ok {
		t.Fatalf("provider %q is not registered", f.Name)
	}
	if p.Description == "" {
		t.Errorf("provider %q has no description", f.Name)
	}
	for _, opt := range p.Options {
		credential := false
		for _, word := range []string{"token", "password", "secret", "key"} {
			credential = credential || strings.Contains(opt, word)
		}
		if credential && !strings.HasSuffix(opt, "_env") {
			t.Errorf("option %q holds a credential: it must name an environment variable (…_env)", opt)
		}
	}

	ctx := context.Background()
	if !f.Provider.Owns(f.Registry) {
		t.Fatalf("provider does not own %s", f.Registry)
	}
	foreign := name.MustParseReference("registry.example.invalid/x/y:1").Context()
	if f.Name != "docker" && f.Provider.Owns(foreign.RegistryStr()) {
		t.Errorf("provider claims a registry it was not given: %s", foreign.RegistryStr())
	}
	if auth, err := f.Provider.Resolve(foreign); err != nil || (f.Name != "docker" && auth != authn.Anonymous) {
		t.Errorf("credentials for a foreign registry must be anonymous: %v %v", auth, err)
	}

	repo, err := name.NewRepository(f.Repo, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 3
	tags, err := f.Provider.Tags(ctx, repo, limit)
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	if len(tags) != limit {
		t.Errorf("tags: got %d, want the limit %d", len(tags), limit)
	}
	for _, tag := range tags {
		if _, err := name.NewTag(repo.Name()+":"+tag.Name, name.StrictValidation); err != nil {
			t.Errorf("invalid tag %q returned", tag.Name)
		}
	}

	repos, err := f.Provider.Repositories(ctx, f.Registry, "", limit)
	switch {
	case f.Repositories == 0:
		if !errors.Is(err, oci.ErrListingUnsupported) {
			t.Errorf("a provider that does not list repositories must say so with ErrListingUnsupported, got %v", err)
		}
	case err != nil:
		t.Errorf("repositories: %v", err)
	case len(repos) != limit:
		t.Errorf("repositories: got %d, want the limit %d", len(repos), limit)
	default:
		for _, r := range repos {
			if parsed, err := name.NewRepository(r, name.StrictValidation); err != nil || parsed.RegistryStr() != f.Registry {
				t.Errorf("repository %q is invalid or not in %s", r, f.Registry)
			}
		}
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.Provider.Tags(cancelled, repo, limit); err == nil {
		t.Error("listing must honour context cancellation")
	}

	deniedRepo, err := name.NewRepository(f.DeniedRegistry+"/"+repo.RepositoryStr(), name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	for what, err := range map[string]error{
		"tags":         second(f.Denied.Tags(ctx, deniedRepo, limit)),
		"repositories": second(f.Denied.Repositories(ctx, f.DeniedRegistry, "", limit)),
	} {
		if what == "repositories" && f.Repositories == 0 {
			continue
		}
		if !errors.Is(err, oci.ErrAuth) {
			t.Errorf("%s with rejected credentials: want ErrAuth, got %v", what, err)
		}
		if err != nil && f.Secret != "" && strings.Contains(err.Error(), f.Secret) {
			t.Errorf("%s: the error contains the credential", what)
		}
	}
}

func second[T any](_ T, err error) error { return err }

// FakeRegistry is a v2 registry that requires basic auth with user and password and serves
// repos repositories (team/app0 …) with tags tags each (1.0.0 …), 2 per page so that
// listing has to follow pages.
func FakeRegistry(t *testing.T, user, password string, repos, tags int) *httptest.Server {
	t.Helper()
	var all []string
	for i := range repos {
		all = append(all, fmt.Sprintf("team/app%d", i))
	}
	sort.Strings(all)
	var tagNames []string
	for i := range tags {
		tagNames = append(tagNames, fmt.Sprintf("1.%d.0", i))
	}
	sort.Strings(tagNames)
	page := func(w http.ResponseWriter, items []string, r *http.Request) []string {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		n = min(max(n, 1), 2)
		last := r.URL.Query().Get("last")
		i := sort.SearchStrings(items, last)
		if i < len(items) && items[i] == last {
			i++
		}
		end := min(i+n, len(items))
		if end < len(items) {
			w.Header().Set("Link", fmt.Sprintf(`<%s?n=%d&last=%s>; rel="next"`, r.URL.Path, n, items[end-1]))
		}
		return items[i:end]
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != user || p != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v2/":
			_, _ = w.Write([]byte("{}"))
		case r.URL.Path == "/v2/_catalog":
			_ = json.NewEncoder(w).Encode(map[string]any{"repositories": page(w, all, r)})
		case strings.HasSuffix(r.URL.Path, "/tags/list"):
			repo := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v2/"), "/tags/list")
			_ = json.NewEncoder(w).Encode(map[string]any{"name": repo, "tags": page(w, tagNames, r)})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
