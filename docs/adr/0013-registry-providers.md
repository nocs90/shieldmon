# 0013 — Registry providers: credentials and listing as an extension point

- Status: accepted
- Date: 2026-10-27

## Context

- Credentials come from one keychain wired in `internal/oci`: docker config and credential
  helpers, then Amazon ECR through the AWS default chain, then Google ADC. It cannot assume a
  role in another AWS account, knows nothing about GitLab, and cannot be extended without
  editing core code (ADR 0008).
- F1 and F12 need listing: "all repositories of a group", "tags of a repository, newest
  first". The registry v2 API lists tags everywhere, but `_catalog` is missing on ECR and
  GitLab, and only ECR's own API says when a tag was pushed.
- A registry is hostile input (I7): a listing can be endless, huge, or full of names that are
  not valid references.
- Credentials must be short-lived and never sit in config or logs (S2).

## Decision

1. **Extension point.** `oci.Provider` is an `authn.Keychain` that answers only for the
   registries it owns (anonymous otherwise), plus `Repositories` and `Tags`, both with a
   limit. `oci.RegisterProvider` registers it from `init` with a description, its option
   keys, and a default order; `shieldmon plugins` lists providers. The kit
   `ocitest.CheckProvider` is the contract.
2. **Built-ins, unchanged behaviour.** `docker` (docker config and helpers; owns every host),
   `ecr` (AWS default chain; owns private ECR hosts of every partition) and `google`
   (ADC; owns GCR and Artifact Registry) apply without configuration, in that order, as the
   keychain did. `gitlab` applies only where configured.
3. **Configuration.** `registries:` binds host patterns (`host` or `*.suffix`) to a provider
   with options, validated at startup like scanner options. Rules come before the built-ins,
   in file order. Options never hold a credential: they name environment variables
   (`*_env`), and a value that looks like a credential is refused.
4. **ECR.** The provider calls ECR itself (`GetAuthorizationToken`, `DescribeRepositories`,
   `DescribeImages`) with the AWS default chain, which covers IRSA, EKS Pod Identity and
   OIDC web identity from CI (GitHub, GitLab `id_tokens`). `role_arn` assumes a role, for
   other accounts. The region and account come from the host, for every partition.
   Authorization tokens are cached in memory until shortly before they expire. Tags are
   listed with their push time, so "newest first" is exact.
5. **GitLab.** Pulls use the CI job token or a deploy token (`read_registry`), read from the
   environment; repositories are listed through the REST API of the configured instance
   (`api_url`, so self-managed works) with a job token or an access token (`read_api`).
   GitLab `id_tokens` authenticate to other services, not to GitLab's registry: they serve
   ECR through web identity (4).
6. **Bounded listing.** Every listing stops at its limit, at 100 pages and at 4 MiB per
   response; every repository and tag name is parsed as a reference and dropped if invalid.
   Generic registries are listed through the v2 API (`_catalog`, `tags/list`).

## Consequences

- Existing setups keep working with no configuration change; the old `oci.Keychain` becomes
  the built-in providers' chain.
- Cross-account ECR no longer needs the role's credentials in the environment.
- "Newest first" is exact on ECR; elsewhere the v2 API gives no dates, so tags are ordered
  by version, then name.
- ECR's integration test needs a sandbox AWS account reached through GitHub OIDC, and
  GitLab's a project: both CI jobs are skipped until a maintainer configures them.
