package oci_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/oci/ocitest"
)

const (
	glJobToken = "glcbt-64_jobtokenvalue1234567890"
	glAPIToken = "glpat-apitokenvalue1234567890ab"
)

// fakeGitLabAPI serves GET /api/v4/groups/<group>/registry/repositories, 2 per page with
// X-Next-Page, to a request carrying header: value. Repositories live in registry; one entry
// points at another registry and one has an invalid path, and both must be dropped.
func fakeGitLabAPI(t *testing.T, header, value, group, registry string, repos int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(header) != value {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"401 Unauthorized"}`))
			return
		}
		want := "/api/v4/groups/" + strings.ReplaceAll(group, "/", "%2F") + "/registry/repositories"
		if r.URL.EscapedPath() != want {
			http.NotFound(w, r)
			return
		}
		type item struct {
			Path     string `json:"path"`
			Location string `json:"location"`
		}
		items := []item{{Path: "team/elsewhere", Location: "other.example.com/team/elsewhere"}, {Path: "team/../x", Location: registry + "/team/../x"}}
		for i := range repos {
			p := fmt.Sprintf("team/app%d", i)
			items = append(items, item{Path: p, Location: registry + "/" + p})
		}
		pageNo, _ := strconv.Atoi(r.URL.Query().Get("page"))
		from := (max(pageNo, 1) - 1) * 2
		to := min(from+2, len(items))
		if to < len(items) {
			w.Header().Set("X-Next-Page", strconv.Itoa(max(pageNo, 1)+1))
		}
		_ = json.NewEncoder(w).Encode(items[from:to])
	}))
	t.Cleanup(srv.Close)
	return srv
}

func gitlabProvider(t *testing.T, registry, apiURL string, opts oci.ProviderOptions, env map[string]string) oci.Provider {
	t.Helper()
	p, _ := oci.LookupProvider("gitlab")
	inst, err := p.New(oci.ProviderSpec{Hosts: []string{registry}, Options: opts, Env: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	return inst
}

func TestGitLabProviderConforms(t *testing.T) {
	reg := ocitest.FakeRegistry(t, "gitlab-ci-token", glJobToken, 0, 6)
	deniedReg := ocitest.FakeRegistry(t, "gitlab-ci-token", "another-token", 0, 6)
	api := fakeGitLabAPI(t, "PRIVATE-TOKEN", glAPIToken, "team", host(reg), 7)
	deniedAPI := fakeGitLabAPI(t, "PRIVATE-TOKEN", "other", "team", host(deniedReg), 7)
	env := map[string]string{"CI_JOB_TOKEN": glJobToken, "API_TOKEN": glAPIToken}
	opts := oci.ProviderOptions{"group": "team", "api_token_env": "API_TOKEN"}
	ok := gitlabProvider(t, host(reg), api.URL, withAPI(opts, api.URL), env)
	denied := gitlabProvider(t, host(deniedReg), deniedAPI.URL, withAPI(opts, deniedAPI.URL), env)
	ocitest.CheckProvider(t, ocitest.Fixture{
		Name: "gitlab", Provider: ok, Denied: denied, DeniedRegistry: host(deniedReg),
		Registry: host(reg), Repositories: 7, Repo: host(reg) + "/team/app0", Secret: glJobToken,
	})
}

func withAPI(o oci.ProviderOptions, api string) oci.ProviderOptions {
	out := oci.ProviderOptions{"api_url": api}
	for k, v := range o {
		out[k] = v
	}
	return out
}

func TestGitLabProviderListsWithTheJobToken(t *testing.T) {
	reg := ocitest.FakeRegistry(t, "gitlab-ci-token", glJobToken, 0, 1)
	api := fakeGitLabAPI(t, "JOB-TOKEN", glJobToken, "team/sub", host(reg), 3)
	p := gitlabProvider(t, host(reg), api.URL, oci.ProviderOptions{"api_url": api.URL}, map[string]string{"CI_JOB_TOKEN": glJobToken})
	repos, err := p.Repositories(context.Background(), host(reg), "team/sub", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 3 {
		t.Errorf("repositories = %v: the foreign and invalid entries must be dropped", repos)
	}
}

func TestGitLabProviderDeployToken(t *testing.T) {
	p := gitlabProvider(t, "registry.gitlab.example.com", "https://gitlab.example.com",
		oci.ProviderOptions{"api_url": "https://gitlab.example.com", "username": "gitlab+deploy-token-7", "token_env": "DEPLOY_TOKEN"},
		map[string]string{"DEPLOY_TOKEN": "gldt-deploytokenvalue1234567"})
	auth, err := p.Resolve(name.MustParseReference("registry.gitlab.example.com/team/app:1").Context())
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := auth.Authorization()
	if cfg.Username != "gitlab+deploy-token-7" || cfg.Password != "gldt-deploytokenvalue1234567" {
		t.Errorf("deploy token credentials = %+v", cfg)
	}
	if auth, _ := p.Resolve(name.MustParseReference("registry.gitlab.com/team/app:1").Context()); auth != authn.Anonymous {
		t.Error("a registry not bound to the rule must be anonymous")
	}
}

func TestGitLabProviderRefusesUnsafeConfig(t *testing.T) {
	p, _ := oci.LookupProvider("gitlab")
	for what, spec := range map[string]oci.ProviderSpec{
		"no hosts":        {Options: oci.ProviderOptions{}},
		"plain http":      {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"api_url": "http://gitlab.example.com"}},
		"user info":       {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"api_url": "https://u@gitlab.example.com"}},
		"not a url":       {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"api_url": "gitlab.example.com"}},
		"query in a url":  {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"api_url": "https://gitlab.example.com/?x=1"}},
		"wrongly typed":   {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"group": 7}},
		"token env typed": {Hosts: []string{"r.example.com"}, Options: oci.ProviderOptions{"token_env": true}},
	} {
		if _, err := p.New(spec); err == nil {
			t.Errorf("%s: must be refused", what)
		}
	}
}
