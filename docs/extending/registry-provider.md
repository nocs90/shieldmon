# Writing a registry provider

A registry provider gives ShieldMon short-lived credentials for the registries it owns and
lists their repositories and tags ([ADR 0013](../adr/0013-registry-providers.md)). Built-in:
`docker`, `ecr`, `google` (apply without configuration) and `gitlab` (configured hosts only).

## 1. Implement `oci.Provider`

```go
// internal/oci/provider_harbor.go
type harborProvider struct {
	hosts []string
	api   string
	user  string
	token string // from the environment, never from config
}

func (p harborProvider) Owns(registry string) bool { return oci.MatchHost(p.hosts, registry) }

// Resolve answers only for owned registries; anonymous lets the next provider try.
func (p harborProvider) Resolve(r authn.Resource) (authn.Authenticator, error) {
	if !p.Owns(r.RegistryStr()) || p.token == "" {
		return authn.Anonymous, nil
	}
	return &authn.Basic{Username: p.user, Password: p.token}, nil
}

// Repositories uses the registry's own API, bounded: at most limit entries, at most
// 100 pages, every response through oci.ListResponse (4 MiB, 401/403 → oci.ErrAuth).
func (p harborProvider) Repositories(ctx context.Context, registry, prefix string, limit int) ([]string, error) { … }

// Tags can reuse the v2 API; return oci.SortTags order (newest first).
func (p harborProvider) Tags(ctx context.Context, repo name.Repository, limit int) ([]oci.Tag, error) {
	return oci.V2Lister{Keychain: p}.Tags(ctx, repo, limit)
}
```

A provider that cannot list repositories returns `oci.ErrListingUnsupported`.

## 2. Register it

```go
func init() {
	oci.RegisterProvider(oci.ProviderPlugin{
		Name:        "harbor",
		Description: "Harbor robot accounts; lists projects through the Harbor API",
		Options:     []string{"api_url", "user", "token_env"},
		New: func(s oci.ProviderSpec) (oci.Provider, error) {
			token, err := s.Secret("token_env")
			…
		},
	})
}
```

`Default: 0` (the usual case) applies the provider only where configuration binds hosts to
it:

```yaml
registries:
  - hosts: [harbor.example.com]
    provider: harbor
    options: { api_url: https://harbor.example.com, user: robot$shieldmon, token_env: HARBOR_TOKEN }
```

Unknown option keys are rejected at startup, and so is any option value that looks like a
credential: credentials only ever come from environment variables named by `*_env` options,
read with `ProviderSpec.Secret`.

## 3. Prove it

- `ocitest.CheckProvider` with a fake backend (`ocitest.FakeRegistry` serves the v2 API with
  basic auth and paginated listings): what the provider owns, bounded and valid listings,
  cancellation, rejected credentials classified as `oci.ErrAuth`, and the credential absent
  from every error.
- Every name the backend returns is parsed as a reference and dropped if invalid.
- Integration tests against the real service are gated on configuration, like the ECR and
  GitLab jobs (`docs/processes/quality-gates.md`).
