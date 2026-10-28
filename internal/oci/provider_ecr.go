package oci

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	ecrapi "github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"

	"github.com/nocs90/shieldmon/internal/redact"
)

// ECRAPI is the part of the ECR API the provider calls.
type ECRAPI interface {
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
	DescribeRepositories(context.Context, *ecr.DescribeRepositoriesInput, ...func(*ecr.Options)) (*ecr.DescribeRepositoriesOutput, error)
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

// ECRClientFactory returns a client for one region of the registry's partition, FIPS
// endpoints when fips is set.
type ECRClientFactory func(ctx context.Context, region string, fips bool) (ECRAPI, error)

// ecrTokenMargin renews an authorization token this long before ECR says it expires.
const ecrTokenMargin = 5 * time.Minute

// ecrProvider is Amazon ECR through the ECR API: authorization tokens for pulls, and
// repository and image listings with push times (docs/adr/0013-registry-providers.md).
type ecrProvider struct {
	hosts  []string // a rule's hosts; nil for the built-in, which owns every ECR registry
	client ECRClientFactory
	now    func() time.Time

	mu      sync.Mutex
	clients map[string]ECRAPI // by region and FIPS
	tokens  map[string]ecrToken
}

type ecrToken struct {
	user, password string
	expires        time.Time
}

// NewECRProvider builds the ecr provider with the given client factory; nil uses the AWS
// default credential chain, assuming role_arn when the spec sets it. Tests pass a fake.
func NewECRProvider(spec ProviderSpec, client ECRClientFactory) (Provider, error) {
	if client == nil {
		roleARN, err := spec.Options.String("role_arn", "")
		if err != nil {
			return nil, err
		}
		externalID, err := spec.Options.String("external_id", "")
		if err != nil {
			return nil, err
		}
		session, err := spec.Options.String("session_name", "shieldmon")
		if err != nil {
			return nil, err
		}
		if roleARN != "" && !strings.HasPrefix(roleARN, "arn:") {
			return nil, fmt.Errorf("role_arn %q is not an ARN", roleARN)
		}
		client = awsECRClient(roleARN, externalID, session)
	}
	return &ecrProvider{
		hosts: spec.Hosts, client: client, now: time.Now,
		clients: map[string]ECRAPI{}, tokens: map[string]ecrToken{},
	}, nil
}

// awsECRClient loads the AWS default credential chain for the region: environment, SSO and
// profiles, web identity (IRSA, CI OIDC), EKS Pod Identity, instance role. With roleARN it
// assumes that role, for registries in other accounts.
func awsECRClient(roleARN, externalID, session string) ECRClientFactory {
	return func(ctx context.Context, region string, fips bool) (ECRAPI, error) {
		opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
		if fips {
			opts = append(opts, config.WithUseFIPSEndpoint(aws.FIPSEndpointStateEnabled))
		}
		cfg, err := config.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, err
		}
		if roleARN != "" {
			cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN,
				func(o *stscreds.AssumeRoleOptions) {
					o.RoleSessionName = session
					if externalID != "" {
						o.ExternalID = aws.String(externalID)
					}
				}))
		}
		return ecr.NewFromConfig(cfg), nil
	}
}

// registry parses an owned host; ok is false for anything that is not ECR or not this
// provider's.
func (p *ecrProvider) registry(host string) (*ecrapi.Registry, bool) {
	reg, err := ecrapi.ExtractRegistry(host)
	if err != nil {
		return nil, false
	}
	if p.hosts != nil && !MatchHost(p.hosts, host) {
		return nil, false
	}
	return reg, true
}

func (p *ecrProvider) Owns(registry string) bool {
	_, ok := p.registry(registry)
	return ok
}

func (p *ecrProvider) api(ctx context.Context, reg *ecrapi.Registry) (ECRAPI, error) {
	key := fmt.Sprintf("%s/%t", reg.Region, reg.FIPS)
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[key]; ok {
		return c, nil
	}
	c, err := p.client(ctx, reg.Region, reg.FIPS)
	if err != nil {
		return nil, ecrError(err)
	}
	p.clients[key] = c
	return c, nil
}

// Resolve returns a pull token for a private registry, cached in memory until shortly before
// it expires; ECR Public is pulled anonymously.
func (p *ecrProvider) Resolve(res authn.Resource) (authn.Authenticator, error) {
	reg, ok := p.registry(res.RegistryStr())
	if !ok || reg.Service != ecrapi.ServiceECR {
		return authn.Anonymous, nil
	}
	host := res.RegistryStr()
	p.mu.Lock()
	tok, cached := p.tokens[host]
	p.mu.Unlock()
	if cached && p.now().Before(tok.expires.Add(-ecrTokenMargin)) {
		return &authn.Basic{Username: tok.user, Password: tok.password}, nil
	}
	ctx := context.Background()
	c, err := p.api(ctx, reg)
	if err != nil {
		return nil, err
	}
	// The token is valid for every registry the identity may read in this region.
	out, err := c.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, ecrError(err)
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return nil, fmt.Errorf("%w: ECR returned no authorization token for %s", ErrAuth, host)
	}
	data := out.AuthorizationData[0]
	raw, err := base64.StdEncoding.DecodeString(aws.ToString(data.AuthorizationToken))
	if err != nil {
		return nil, fmt.Errorf("ECR authorization token for %s: %w", host, err)
	}
	user, password, found := strings.Cut(string(raw), ":")
	if !found {
		return nil, fmt.Errorf("ECR authorization token for %s is malformed", host)
	}
	tok = ecrToken{user: user, password: password, expires: aws.ToTime(data.ExpiresAt)}
	p.mu.Lock()
	p.tokens[host] = tok
	p.mu.Unlock()
	return &authn.Basic{Username: user, Password: password}, nil
}

// Repositories pages through DescribeRepositories of the registry's account.
func (p *ecrProvider) Repositories(ctx context.Context, registry, prefix string, limit int) ([]string, error) {
	reg, ok := p.registry(registry)
	if !ok {
		return nil, fmt.Errorf("ecr: %s is not an ECR registry of this provider", registry)
	}
	if reg.Service != ecrapi.ServiceECR {
		return nil, errNoListing("ecr")
	}
	c, err := p.api(ctx, reg)
	if err != nil {
		return nil, err
	}
	var out []string
	in := &ecr.DescribeRepositoriesInput{RegistryId: aws.String(reg.ID), MaxResults: aws.Int32(listPageSize)}
	for page := 0; page < listMaxPages && len(out) < limit; page++ {
		resp, err := c.DescribeRepositories(ctx, in)
		if err != nil {
			return nil, ecrError(err)
		}
		for _, r := range resp.Repositories {
			repoName := aws.ToString(r.RepositoryName)
			if full, ok := validRepository(registry, repoName); ok && strings.HasPrefix(repoName, prefix) && len(out) < limit {
				out = append(out, full)
			}
		}
		if resp.NextToken == nil {
			break
		}
		in.NextToken = resp.NextToken
	}
	return out, nil
}

// Tags pages through DescribeImages and returns the newest tags by push time. ECR Public is
// listed through the v2 API, anonymously.
func (p *ecrProvider) Tags(ctx context.Context, repo name.Repository, limit int) ([]Tag, error) {
	reg, ok := p.registry(repo.RegistryStr())
	if !ok {
		return nil, fmt.Errorf("ecr: %s is not an ECR registry of this provider", repo.RegistryStr())
	}
	if reg.Service != ecrapi.ServiceECR {
		return V2Lister{Keychain: authn.NewMultiKeychain()}.Tags(ctx, repo, limit)
	}
	c, err := p.api(ctx, reg)
	if err != nil {
		return nil, err
	}
	var tags []Tag
	in := &ecr.DescribeImagesInput{
		RegistryId: aws.String(reg.ID), RepositoryName: aws.String(repo.RepositoryStr()),
		Filter: &ecrtypes.DescribeImagesFilter{TagStatus: ecrtypes.TagStatusTagged}, MaxResults: aws.Int32(listPageSize),
	}
	for page := 0; page < listMaxPages; page++ {
		resp, err := c.DescribeImages(ctx, in)
		if err != nil {
			return nil, ecrError(err)
		}
		for _, img := range resp.ImageDetails {
			for _, t := range img.ImageTags {
				if _, err := name.NewTag(repo.Name()+":"+t, name.StrictValidation); err == nil {
					tags = append(tags, Tag{Name: t, Pushed: aws.ToTime(img.ImagePushedAt)})
				}
			}
		}
		if resp.NextToken == nil {
			break
		}
		in.NextToken = resp.NextToken
	}
	SortTags(tags)
	return tags[:min(len(tags), limit)], nil
}

// ecrError marks credential and permission failures as ErrAuth, so that they open a
// registry_auth health finding, and redacts the message: AWS errors can echo request data.
func ecrError(err error) error {
	msg := redact.Error(err)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException",
			"ExpiredTokenException", "InvalidClientTokenId", "AccessDenied":
			return fmt.Errorf("%w: %s", ErrAuth, msg)
		}
	}
	if strings.Contains(msg, "failed to retrieve credentials") || strings.Contains(msg, "failed to refresh cached credentials") {
		return fmt.Errorf("%w: no AWS credentials: %s", ErrAuth, msg)
	}
	return fmt.Errorf("ecr: %s", msg)
}
