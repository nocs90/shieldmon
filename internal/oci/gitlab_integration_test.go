//go:build integration

package oci_test

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/oci"
)

// TestGitLabIntegration runs the gitlab provider against a real project with at least one
// tagged image (ci/gitlab). SHIELDMON_TEST_GITLAB_REPO names the image repository, e.g.
// registry.gitlab.com/group/project/app; SHIELDMON_TEST_GITLAB_API the instance
// (https://gitlab.com by default); SHIELDMON_GITLAB_API_TOKEN a read_api token and
// SHIELDMON_GITLAB_DEPLOY_USER / SHIELDMON_GITLAB_DEPLOY_TOKEN a read_registry deploy token.
func TestGitLabIntegration(t *testing.T) {
	ref := os.Getenv("SHIELDMON_TEST_GITLAB_REPO")
	if ref == "" {
		t.Skip("SHIELDMON_TEST_GITLAB_REPO not set")
	}
	repo, err := name.NewRepository(ref, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	api := os.Getenv("SHIELDMON_TEST_GITLAB_API")
	if api == "" {
		api = "https://gitlab.com"
	}
	regs, err := oci.NewRegistries([]oci.Rule{{
		Hosts: []string{repo.RegistryStr()}, Provider: "gitlab",
		Options: map[string]any{
			"api_url": api, "username": os.Getenv("SHIELDMON_GITLAB_DEPLOY_USER"),
			"token_env": "SHIELDMON_GITLAB_DEPLOY_TOKEN", "api_token_env": "SHIELDMON_GITLAB_API_TOKEN",
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	p, err := regs.For(repo.RegistryStr())
	if err != nil {
		t.Fatal(err)
	}
	// The project path is the repository path up to its last element at most.
	project := repo.RepositoryStr()
	if i := strings.LastIndex(project, "/"); i > 0 {
		project = project[:i]
	}
	repos, err := p.Repositories(ctx, repo.RegistryStr(), project, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(repos, repo.Name()) {
		t.Fatalf("listing of %s lacks %s: %v", project, repo.Name(), repos)
	}
	tags, err := p.Tags(ctx, repo, 5)
	if err != nil || len(tags) == 0 {
		t.Fatalf("tags: %v %v", tags, err)
	}
	if _, err := oci.Resolve(ctx, repo.Name()+":"+tags[0].Name, oci.Options{Keychain: regs}); err != nil {
		t.Fatalf("resolve with the deploy token: %v", err)
	}
}
