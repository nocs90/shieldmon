package oci

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/redact"
)

// gitlabJobTokenUser is the user name GitLab's registry expects with a CI job token.
const gitlabJobTokenUser = "gitlab-ci-token" //nolint:gosec // G101: GitLab's documented user name for job tokens, not a credential

// gitlabProvider is a GitLab container registry, on GitLab.com or self-managed: pulls with a
// CI job token or a deploy token, repositories listed through the instance's REST API
// (docs/adr/0013-registry-providers.md).
type gitlabProvider struct {
	hosts []string
	api   *url.URL
	group string // listing scope when none is given: a group or project path

	user, token        string // registry credentials (read_registry)
	apiHeader, apiAuth string // REST API credentials: PRIVATE-TOKEN (read_api) or JOB-TOKEN
	client             *http.Client
}

func newGitLabProvider(s ProviderSpec) (Provider, error) {
	if len(s.Hosts) == 0 {
		return nil, errors.New("gitlab applies only to configured hosts")
	}
	apiURL, err := s.Options.String("api_url", "https://gitlab.com")
	if err != nil {
		return nil, err
	}
	api, err := url.Parse(strings.TrimSuffix(apiURL, "/"))
	if err != nil || api.Host == "" || api.User != nil || api.RawQuery != "" {
		return nil, fmt.Errorf("api_url %q: want https://host[/path]", apiURL)
	}
	localHTTP := api.Scheme == "http" && loopback(api.Hostname())
	if api.Scheme != "https" && !localHTTP {
		return nil, fmt.Errorf("api_url %q: https is required (http only for localhost)", apiURL)
	}
	group, err := s.Options.String("group", "")
	if err != nil {
		return nil, err
	}
	user, err := s.Options.String("username", "")
	if err != nil {
		return nil, err
	}
	if _, ok := s.Options["token_env"]; !ok {
		s.Options = withDefault(s.Options, "token_env", "CI_JOB_TOKEN")
	}
	token, err := s.Secret("token_env")
	if err != nil {
		return nil, err
	}
	p := &gitlabProvider{
		hosts: s.Hosts, api: api, group: strings.Trim(group, "/"), user: user, token: token,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	if p.user == "" {
		// Without a deploy token user name, the token is a CI job token.
		p.user = gitlabJobTokenUser
	}
	apiToken, err := s.Secret("api_token_env")
	if err != nil {
		return nil, err
	}
	switch {
	case apiToken != "":
		p.apiHeader, p.apiAuth = "PRIVATE-TOKEN", apiToken
	case p.user == gitlabJobTokenUser && token != "":
		p.apiHeader, p.apiAuth = "JOB-TOKEN", token
	}
	return p, nil
}

func withDefault(o ProviderOptions, key string, v any) ProviderOptions {
	out := ProviderOptions{key: v}
	for k, val := range o {
		out[k] = val
	}
	return out
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *gitlabProvider) Owns(registry string) bool { return MatchHost(p.hosts, registry) }

func (p *gitlabProvider) Resolve(res authn.Resource) (authn.Authenticator, error) {
	if !p.Owns(res.RegistryStr()) || p.token == "" {
		return authn.Anonymous, nil
	}
	return &authn.Basic{Username: p.user, Password: p.token}, nil
}

// Repositories lists the container repositories of a group (with its subgroups' projects) or
// of a project: prefix is its path, or the group option when prefix is empty.
func (p *gitlabProvider) Repositories(ctx context.Context, registry, prefix string, limit int) ([]string, error) {
	if !p.Owns(registry) {
		return nil, fmt.Errorf("gitlab: %s is not a registry of this provider", registry)
	}
	scope := strings.Trim(prefix, "/")
	if scope == "" {
		scope = p.group
	}
	if scope == "" {
		return nil, errors.New("gitlab: give a group or project path to list (or set the group option)")
	}
	if p.apiHeader == "" {
		return nil, fmt.Errorf("%w: gitlab: listing needs api_token_env (read_api) or a CI job token", ErrAuth)
	}
	repos, err := p.listRepositories(ctx, registry, "groups", scope, limit)
	var notFound errNotFound
	if errors.As(err, &notFound) {
		repos, err = p.listRepositories(ctx, registry, "projects", scope, limit)
	}
	if err != nil {
		return nil, gitlabError(err)
	}
	return repos, nil
}

// gitlabError redacts err and keeps ErrAuth recognisable, so that a rejected token opens a
// registry_auth health finding without the token in it.
func gitlabError(err error) error {
	if errors.Is(err, ErrAuth) {
		return fmt.Errorf("%w: gitlab: %s", ErrAuth, redact.Error(err))
	}
	return fmt.Errorf("gitlab: %s", redact.Error(err))
}

type errNotFound struct{ status string }

func (e errNotFound) Error() string { return e.status }

func (p *gitlabProvider) listRepositories(ctx context.Context, registry, kind, path string, limit int) ([]string, error) {
	var out []string
	pageNo := "1"
	for page := 0; page < listMaxPages && len(out) < limit && pageNo != ""; page++ {
		// GitLab takes the group or project path as one URL-encoded segment (team%2Fsub).
		u := *p.api
		u.RawPath = p.api.EscapedPath() + "/api/v4/" + kind + "/" + url.PathEscape(path) + "/registry/repositories"
		u.Path = p.api.Path + "/api/v4/" + kind + "/" + path + "/registry/repositories"
		q := url.Values{"per_page": {strconv.Itoa(listPageSize)}, "page": {pageNo}}
		if kind == "groups" {
			q.Set("include_subgroups", "true")
		}
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set(p.apiHeader, p.apiAuth)
		resp, err := p.client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			return nil, errNotFound{resp.Status}
		}
		pageNo = resp.Header.Get("X-Next-Page")
		var items []struct {
			Path     string `json:"path"`
			Location string `json:"location"`
		}
		if err := ListResponse(resp, &items); err != nil {
			return nil, err
		}
		for _, it := range items {
			// The location names the registry; one on another host is not this provider's.
			if !strings.HasPrefix(it.Location, registry+"/") {
				continue
			}
			if full, ok := validRepository(registry, it.Path); ok && len(out) < limit {
				out = append(out, full)
			}
		}
		if _, err := strconv.Atoi(pageNo); pageNo != "" && err != nil {
			return nil, fmt.Errorf("invalid X-Next-Page %q", pageNo)
		}
	}
	return out, nil
}

// Tags lists through the registry v2 API with the registry credentials.
func (p *gitlabProvider) Tags(ctx context.Context, repo name.Repository, limit int) ([]Tag, error) {
	if !p.Owns(repo.RegistryStr()) {
		return nil, fmt.Errorf("gitlab: %s is not a registry of this provider", repo.RegistryStr())
	}
	tags, err := V2Lister{Keychain: p}.Tags(ctx, repo, limit)
	if err != nil {
		return nil, gitlabError(err)
	}
	return tags, nil
}

func init() {
	RegisterProvider(ProviderPlugin{
		Name:        "gitlab",
		Description: "GitLab.com and self-managed registries: CI job token or deploy token (read_registry) for pulls; group and project listing through the REST API",
		Options:     []string{"api_url", "group", "username", "token_env", "api_token_env"},
		New:         newGitLabProvider,
	})
}
