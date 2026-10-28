package oci

import (
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
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
		Description: "Amazon ECR, every partition and ECR Public, through the AWS default credential chain (IRSA, EKS Pod Identity, web identity, SSO, instance role); role_arn for other accounts; lists repositories and tags with push times",
		Options:     []string{"role_arn", "external_id", "session_name"},
		Default:     2,
		New:         func(s ProviderSpec) (Provider, error) { return NewECRProvider(s, nil) },
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
