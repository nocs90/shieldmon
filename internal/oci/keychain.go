package oci

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	ecrapi "github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

var (
	keychainOnce sync.Once
	keychain     authn.Keychain
)

// Keychain is the chain of built-in providers, used when no registries: rules are configured
// (docs/processes/registries.md), first match wins:
//
//  1. docker: docker config and credential helpers (`docker login`, docker-credential-*);
//  2. ecr: Amazon ECR private registries in any account and region, including every AWS
//     partition and FIPS endpoints, through the AWS default credential chain (environment,
//     SSO/profile, web identity, IRSA, EKS Pod Identity, instance role);
//  3. google: Google Container Registry / Artifact Registry through gcloud or Application
//     Default Credentials.
//
// Anything else is anonymous, which covers public images on every registry.
func Keychain() authn.Keychain {
	keychainOnce.Do(func() {
		r, err := NewRegistries(nil)
		if err != nil {
			panic("oci: built-in providers: " + err.Error()) // built-ins take no options
		}
		keychain = r
	})
	return keychain
}

// dockerProvider is docker config and credential helpers. It owns every registry, so that
// listing works on any registry with the v2 API.
type dockerProvider struct{ V2Lister }

func (dockerProvider) Owns(string) bool { return true }

func (p dockerProvider) Resolve(r authn.Resource) (authn.Authenticator, error) {
	return authn.DefaultKeychain.Resolve(r)
}

// ecrHelperProvider is Amazon ECR through the AWS default credential chain. Credentials are
// short-lived tokens obtained on demand; the helper's on-disk token cache is disabled so that
// no credential is persisted (S2).
type ecrHelperProvider struct {
	kc authn.Keychain
}

func newECRHelperProvider(ProviderSpec) (Provider, error) {
	if os.Getenv("AWS_ECR_DISABLE_CACHE") == "" {
		_ = os.Setenv("AWS_ECR_DISABLE_CACHE", "true")
	}
	return ecrHelperProvider{kc: authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard)))}, nil
}

func (ecrHelperProvider) Owns(registry string) bool {
	_, err := ecrapi.ExtractRegistry(registry)
	return err == nil
}

func (p ecrHelperProvider) Resolve(r authn.Resource) (authn.Authenticator, error) {
	return p.kc.Resolve(r)
}

func (ecrHelperProvider) Repositories(context.Context, string, string, int) ([]string, error) {
	return nil, errNoListing("ecr")
}

func (p ecrHelperProvider) Tags(ctx context.Context, repo name.Repository, limit int) ([]Tag, error) {
	return V2Lister{Keychain: p.kc}.Tags(ctx, repo, limit)
}

// googleProvider is GCR and Artifact Registry through gcloud or Application Default
// Credentials.
type googleProvider struct{ V2Lister }

func (googleProvider) Owns(registry string) bool {
	return registry == "gcr.io" || strings.HasSuffix(registry, ".gcr.io") || strings.HasSuffix(registry, "-docker.pkg.dev")
}

func (googleProvider) Resolve(r authn.Resource) (authn.Authenticator, error) {
	return google.Keychain.Resolve(r)
}

func init() {
	RegisterProvider(ProviderPlugin{
		Name:        "docker",
		Description: "docker config and credential helpers (docker login, docker-credential-*); lists any registry through the v2 API",
		Default:     1,
		Fallback:    true,
		New: func(ProviderSpec) (Provider, error) {
			return dockerProvider{V2Lister{Keychain: authn.DefaultKeychain}}, nil
		},
	})
	RegisterProvider(ProviderPlugin{
		Name:        "ecr",
		Description: "Amazon ECR, every partition, through the AWS default credential chain (IRSA, EKS Pod Identity, web identity, SSO, instance role)",
		Default:     2,
		New:         newECRHelperProvider,
	})
	RegisterProvider(ProviderPlugin{
		Name:        "google",
		Description: "Google Container Registry and Artifact Registry through gcloud or Application Default Credentials",
		Default:     3,
		New: func(ProviderSpec) (Provider, error) {
			return googleProvider{V2Lister{Keychain: google.Keychain}}, nil
		},
	})
}
