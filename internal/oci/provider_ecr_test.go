package oci_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/smithy-go"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/oci"
	"github.com/nocs90/shieldmon/internal/oci/ocitest"
)

const (
	ecrHost   = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
	ecrSecret = "ecr-pull-password-s3cr3t"
)

// fakeECR serves a registry with repos repositories and an image per tag (pushed one hour
// apart), 2 entries per page; denied answers AccessDeniedException.
type fakeECR struct {
	repos, tags int
	denied      bool
	tokenCalls  int
	regions     []string
}

func (f *fakeECR) err() error {
	return &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform ecr:GetAuthorizationToken (password=" + ecrSecret + ")"}
}

func (f *fakeECR) GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	f.tokenCalls++
	if f.denied {
		return nil, f.err()
	}
	tok := base64.StdEncoding.EncodeToString([]byte("AWS:" + ecrSecret))
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{
		AuthorizationToken: aws.String(tok), ExpiresAt: aws.Time(time.Now().Add(12 * time.Hour)),
	}}}, nil
}

// page returns items [from, from+2) of n and the next token.
func page(next *string, n int) (int, int, *string) {
	from := 0
	if next != nil {
		fmt.Sscan(*next, &from)
	}
	to := min(from+2, n)
	if to < n {
		return from, to, aws.String(fmt.Sprint(to))
	}
	return from, to, nil
}

func (f *fakeECR) DescribeRepositories(ctx context.Context, in *ecr.DescribeRepositoriesInput, _ ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.denied {
		return nil, f.err()
	}
	from, to, next := page(in.NextToken, f.repos)
	out := &ecr.DescribeRepositoriesOutput{NextToken: next}
	for i := from; i < to; i++ {
		out.Repositories = append(out.Repositories, ecrtypes.Repository{RepositoryName: aws.String(fmt.Sprintf("team/app%d", i))})
	}
	return out, nil
}

func (f *fakeECR) DescribeImages(ctx context.Context, in *ecr.DescribeImagesInput, _ ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.denied {
		return nil, f.err()
	}
	from, to, next := page(in.NextToken, f.tags)
	out := &ecr.DescribeImagesOutput{NextToken: next}
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := from; i < to; i++ {
		out.ImageDetails = append(out.ImageDetails, ecrtypes.ImageDetail{
			ImageTags: []string{fmt.Sprintf("build-%d", i)}, ImagePushedAt: aws.Time(base.Add(time.Duration(i) * time.Hour)),
		})
	}
	return out, nil
}

func ecrProvider(t *testing.T, f *fakeECR, spec oci.ProviderSpec) oci.Provider {
	t.Helper()
	p, err := oci.NewECRProvider(spec, func(_ context.Context, region string, _ bool) (oci.ECRAPI, error) {
		f.regions = append(f.regions, region)
		return f, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestECRProviderConforms(t *testing.T) {
	ok := ecrProvider(t, &fakeECR{repos: 7, tags: 6}, oci.ProviderSpec{})
	denied := ecrProvider(t, &fakeECR{denied: true}, oci.ProviderSpec{})
	ocitest.CheckProvider(t, ocitest.Fixture{
		Name: "ecr", Provider: ok, Denied: denied, DeniedRegistry: ecrHost,
		Registry: ecrHost, Repositories: 7, Repo: ecrHost + "/team/app0", Secret: ecrSecret,
	})
}

func TestECRProviderCredentials(t *testing.T) {
	f := &fakeECR{}
	p := ecrProvider(t, f, oci.ProviderSpec{})
	repo := name.MustParseReference(ecrHost + "/team/app:1").Context()
	for range 3 {
		auth, err := p.Resolve(repo)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := auth.Authorization()
		if cfg.Username != "AWS" || cfg.Password != ecrSecret {
			t.Fatalf("credentials = %+v", cfg)
		}
	}
	if f.tokenCalls != 1 {
		t.Errorf("the token must be cached until it nears expiry: %d calls", f.tokenCalls)
	}
	if strings.Join(f.regions, ",") != "eu-west-1" {
		t.Errorf("client regions = %v, want the registry's", f.regions)
	}
	for _, public := range []string{"public.ecr.aws/docker/library/alpine:3", "quay.io/x/y:1"} {
		ref, err := name.ParseReference(public)
		if err != nil {
			t.Fatal(err)
		}
		if auth, err := p.Resolve(ref.Context()); err != nil || auth != authn.Anonymous {
			t.Errorf("%s must be anonymous: %v %v", public, auth, err)
		}
	}
	for _, host := range []string{
		"123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn",
		"123456789012.dkr.ecr-fips.us-gov-west-1.amazonaws.com",
		"123456789012.dkr.ecr.us-iso-east-1.c2s.ic.gov",
	} {
		if !p.Owns(host) {
			t.Errorf("the built-in provider must own %s (every partition)", host)
		}
	}
}

func TestECRProviderRuleOwnsItsHostsOnly(t *testing.T) {
	other := "210987654321.dkr.ecr.eu-west-1.amazonaws.com"
	p := ecrProvider(t, &fakeECR{}, oci.ProviderSpec{Hosts: []string{other}})
	if !p.Owns(other) || p.Owns(ecrHost) {
		t.Error("a rule's provider must own exactly the rule's hosts")
	}
	if _, err := oci.NewECRProvider(oci.ProviderSpec{Options: oci.ProviderOptions{"role_arn": "shieldmon-read"}}, nil); err == nil {
		t.Error("role_arn must be an ARN")
	}
}

func TestECRProviderTagsNewestFirst(t *testing.T) {
	p := ecrProvider(t, &fakeECR{tags: 5}, oci.ProviderSpec{})
	tags, err := p.Tags(context.Background(), name.MustParseReference(ecrHost+"/team/app:1").Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0].Name != "build-4" || tags[1].Name != "build-3" {
		t.Errorf("newest tags by push time = %+v", tags)
	}
}
