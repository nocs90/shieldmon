package oci

import (
	"io"
	"os"
	"sync"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
)

var (
	keychainOnce sync.Once
	keychain     authn.Keychain
)

// Keychain is the credential chain used for registries, first match wins
// (docs/processes/registries.md):
//
//  1. docker config and credential helpers (`docker login`, docker-credential-*);
//  2. Amazon ECR private registries in any account and region, including
//     every AWS partition and FIPS endpoints, through the AWS default credential chain
//     (environment, SSO/profile, IRSA, EKS Pod Identity, instance role);
//  3. Google Container Registry / Artifact Registry through gcloud or
//     Application Default Credentials.
//
// Anything else is anonymous, which covers public images on every registry.
// Credentials are short-lived tokens obtained on demand; the ECR helper's
// on-disk token cache is disabled so that no credential is persisted (S2).
func Keychain() authn.Keychain {
	keychainOnce.Do(func() {
		if os.Getenv("AWS_ECR_DISABLE_CACHE") == "" {
			_ = os.Setenv("AWS_ECR_DISABLE_CACHE", "true")
		}
		keychain = authn.NewMultiKeychain(
			authn.DefaultKeychain,
			authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))),
			google.Keychain,
		)
	})
	return keychain
}
