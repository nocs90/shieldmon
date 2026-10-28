package oci_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/oci/ocitest"
)

// dockerConfig points DOCKER_CONFIG at a config with user:password for each host.
func dockerConfig(t *testing.T, user, password string, hosts ...string) {
	t.Helper()
	auths := map[string]any{}
	for _, h := range hosts {
		auths[h] = map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte(user + ":" + password))}
	}
	dir := t.TempDir()
	b, _ := json.Marshal(map[string]any{"auths": auths})
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
}

func host(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "http://") }

func TestDockerProviderConforms(t *testing.T) {
	const secret = "s3cr3t-docker-password"
	ok := ocitest.FakeRegistry(t, "robot", secret, 7, 6)
	denied := ocitest.FakeRegistry(t, "robot", "another-password", 7, 6)
	dockerConfig(t, "robot", secret, host(ok), host(denied))
	p, _ := oci.LookupProvider("docker")
	inst, err := p.New(oci.ProviderSpec{})
	if err != nil {
		t.Fatal(err)
	}
	ocitest.CheckProvider(t, ocitest.Fixture{
		Name: "docker", Provider: inst, Denied: inst, DeniedRegistry: host(denied),
		Registry: host(ok), Repositories: 7, Repo: host(ok) + "/team/app0", Secret: secret,
	})
}

// testProvider owns its configured hosts and nothing else.
type testProvider struct {
	oci.V2Lister
	hosts []string
}

func (p testProvider) Owns(r string) bool { return oci.MatchHost(p.hosts, r) }
func (p testProvider) Resolve(r authn.Resource) (authn.Authenticator, error) {
	if !p.Owns(r.RegistryStr()) {
		return authn.Anonymous, nil
	}
	return &authn.Basic{Username: "rule", Password: "from-env"}, nil
}

func init() {
	oci.RegisterProvider(oci.ProviderPlugin{
		Name: "testprov", Description: "test provider", Options: []string{"api_url", "token_env"},
		New: func(s oci.ProviderSpec) (oci.Provider, error) { return testProvider{hosts: s.Hosts}, nil },
	})
}

func TestNewRegistriesValidatesRules(t *testing.T) {
	for what, rule := range map[string]oci.Rule{
		"unknown provider":    {Hosts: []string{"r.example.com"}, Provider: "nope"},
		"no hosts":            {Provider: "testprov"},
		"host with a path":    {Hosts: []string{"r.example.com/team"}, Provider: "testprov"},
		"unknown option":      {Hosts: []string{"r.example.com"}, Provider: "testprov", Options: map[string]any{"tokn_env": "X"}},
		"literal credential":  {Hosts: []string{"r.example.com"}, Provider: "testprov", Options: map[string]any{"api_url": "https://u:glpat-abcdefghijklmnopqrst@gitlab.example.com"}},
		"credential in value": {Hosts: []string{"r.example.com"}, Provider: "testprov", Options: map[string]any{"token_env": "glpat-abcdefghijklmnopqrst"}},
	} {
		if _, err := oci.NewRegistries([]oci.Rule{rule}); err == nil {
			t.Errorf("%s: rule %+v must be refused", what, rule)
		}
	}
	if _, err := oci.NewRegistries([]oci.Rule{{Hosts: []string{"*.example.com", "r.example.org:5000"}, Provider: "testprov", Options: map[string]any{"token_env": "CI_JOB_TOKEN"}}}); err != nil {
		t.Errorf("a valid rule was refused: %v", err)
	}
}

func TestRegistriesRouteRulesFirst(t *testing.T) {
	r, err := oci.NewRegistries([]oci.Rule{{Hosts: []string{"*.example.com"}, Provider: "testprov"}})
	if err != nil {
		t.Fatal(err)
	}
	if p, _ := r.For("registry.example.com"); fmt.Sprintf("%T", p) != "oci_test.testProvider" {
		t.Errorf("a configured host must go to its rule's provider, got %T", p)
	}
	if p, _ := r.For("quay.io"); p == nil {
		t.Error("any other registry must still have a provider (docker)")
	}
	// docker owns every registry and comes first for credentials, but a registry with a
	// provider of its own is listed by that provider.
	if p, _ := r.For("123456789012.dkr.ecr.eu-west-1.amazonaws.com"); !p.Owns("123456789012.dkr.ecr.eu-west-1.amazonaws.com") || p.Owns("quay.io") {
		t.Errorf("an ECR registry must be listed by the ecr provider, got %T", p)
	}
	auth, err := r.Resolve(name.MustParseReference("registry.example.com/team/app:1").Context())
	if err != nil || auth == authn.Anonymous {
		t.Errorf("rule credentials must come before the built-ins: %v %v", auth, err)
	}
}

func TestMatchHost(t *testing.T) {
	for _, c := range []struct {
		patterns []string
		host     string
		want     bool
	}{
		{[]string{"registry.gitlab.com"}, "registry.gitlab.com", true},
		{[]string{"registry.gitlab.com"}, "evil-registry.gitlab.com", false},
		{[]string{"*.example.com"}, "r.EXAMPLE.com", true},
		{[]string{"*.example.com"}, "example.com", false},
		{[]string{"*.example.com"}, "r.example.com.evil.io", false},
		{[]string{"r.example.com:5000"}, "r.example.com", false},
	} {
		if got := oci.MatchHost(c.patterns, c.host); got != c.want {
			t.Errorf("MatchHost(%q, %q) = %t", c.patterns, c.host, got)
		}
	}
}

// TestV2ListerIsBounded serves a hostile registry: endless pages, invalid names, a huge body.
func TestV2ListerIsBounded(t *testing.T) {
	var requests atomic.Int64
	huge := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/v2/" {
			return
		}
		if huge {
			_, _ = w.Write([]byte(`{"tags":["` + strings.Repeat("a", 5<<20) + `"]}`))
			return
		}
		// Always one more page, and the same "last" each time.
		w.Header().Set("Link", `</v2/x/y/tags/list?n=2&last=1.0>; rel="next"`)
		_, _ = w.Write([]byte(`{"tags":["1.0","../../etc","` + strings.Repeat("x", 200) + `","2.0"]}`))
	}))
	defer srv.Close()
	repo, err := name.NewRepository(host(srv) + "/x/y")
	if err != nil {
		t.Fatal(err)
	}
	l := oci.V2Lister{Keychain: authn.NewMultiKeychain()}
	tags, err := l.Tags(context.Background(), repo, 10)
	if err != nil {
		t.Fatal(err)
	}
	if n := requests.Load(); n > 101 {
		t.Errorf("an endless listing made %d requests", n)
	}
	for _, tag := range tags {
		if tag.Name != "1.0" && tag.Name != "2.0" {
			t.Errorf("invalid tag %q returned", tag.Name)
		}
	}
	huge = true
	if _, err := l.Tags(context.Background(), repo, 10); !errors.Is(err, oci.ErrLimit) {
		t.Errorf("an oversized response must fail with ErrLimit, got %v", err)
	}
}

func TestSortTagsNewestFirst(t *testing.T) {
	now := time.Now()
	tags := []oci.Tag{{Name: "1.9.0"}, {Name: "latest"}, {Name: "1.10.0"}, {Name: "v2.0.0-rc1"}, {Name: "old", Pushed: now.Add(-time.Hour)}, {Name: "new", Pushed: now}}
	oci.SortTags(tags)
	var got []string
	for _, t := range tags {
		got = append(got, t.Name)
	}
	if want := "new old v2.0.0-rc1 1.10.0 1.9.0 latest"; strings.Join(got, " ") != want {
		t.Errorf("order = %s, want %s", strings.Join(got, " "), want)
	}
}

// TestV2ListerDropsHostileRepositoryNames: go-containerregistry only checks characters, so a
// registry could slip path traversal into names that end up in URLs and targets.
func TestV2ListerDropsHostileRepositoryNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}
		_, _ = w.Write([]byte(`{"repositories":["team/app","team/../etc","team/./x","Team/Upper","a//b","-x/y","x/y-","` + strings.Repeat("a", 256) + `"]}`))
	}))
	defer srv.Close()
	repos, err := oci.V2Lister{Keychain: authn.NewMultiKeychain()}.Repositories(context.Background(), host(srv), "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 1 || repos[0] != host(srv)+"/team/app" {
		t.Errorf("repositories = %q, want only team/app", repos)
	}
}
