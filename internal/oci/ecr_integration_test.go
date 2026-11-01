//go:build integration

package oci_test

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/model"
	"github.com/nocs90/shieldmon/internal/oci"
)

// TestECRIntegration runs the built-in ecr provider against a real repository with at least
// one tag, with whatever credentials the AWS default chain finds (ci/ecr: GitHub OIDC into a
// sandbox account, no static keys). SHIELDMON_TEST_ECR_REPO names the repository,
// e.g. 123456789012.dkr.ecr.eu-west-1.amazonaws.com/shieldmon-ci.
func TestECRIntegration(t *testing.T) {
	ref := os.Getenv("SHIELDMON_TEST_ECR_REPO")
	if ref == "" {
		t.Skip("SHIELDMON_TEST_ECR_REPO not set")
	}
	repo, err := name.NewRepository(ref, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	regs, err := oci.NewRegistries(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := regs.For(repo.RegistryStr())
	if err != nil {
		t.Fatal(err)
	}
	repos, err := p.Repositories(ctx, repo.RegistryStr(), repo.RepositoryStr(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(repos, repo.Name()) {
		t.Fatalf("repository listing %v lacks %s", repos, repo.Name())
	}
	tags, err := p.Tags(ctx, repo, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) == 0 || tags[0].Pushed.IsZero() {
		t.Fatalf("ECR tags must come with push times: %+v", tags)
	}
	r, err := oci.Resolve(ctx, repo.Name()+":"+tags[0].Name, oci.Options{Keychain: regs, Platform: model.Platform{OS: "linux", Architecture: "amd64"}})
	if err != nil {
		t.Fatalf("resolve with the provider's pull token: %v", err)
	}
	t.Logf("%s:%s → %s", repo.Name(), tags[0].Name, r.Digest)
}
