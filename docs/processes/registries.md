# Registries and credentials

ShieldMon talks to registries itself (no Docker daemon) and never passes credentials to
scanners. Public images on any registry need no configuration.

| Registry | Public images | Private images |
|---|---|---|
| Docker Hub `docker.io` | ✅ anonymous | `docker login` (docker config) |
| Amazon ECR `<acct>.dkr.ecr.<region>.amazonaws.com` (any AWS partition, FIPS endpoints) | — | ✅ native: AWS default credential chain (env, SSO/profile, IRSA, EKS Pod Identity, instance role). Cross-account works through the role's ECR permissions. |
| Amazon ECR Public `public.ecr.aws` | ✅ anonymous | — |
| Google GCR `gcr.io`, Artifact Registry `*-docker.pkg.dev` | ✅ anonymous | ✅ native: gcloud or Application Default Credentials |
| GitHub `ghcr.io`, Quay `quay.io`, Microsoft `mcr.microsoft.com`, Red Hat `registry.access.redhat.com` | ✅ anonymous | `docker login` |
| Azure ACR, GitLab, Harbor, Zot, self-hosted | ✅ anonymous if public | `docker login` or a docker credential helper |

Resolution order (first match wins): docker config and credential helpers → ECR → Google
→ anonymous. A registry that answers 401/403 opens a `registry_auth` health finding.

## Recommended practice

- Use **short-lived credentials** only: IAM roles (IRSA / Pod Identity) for ECR, Workload
  Identity / ADC for Google, CI job tokens or deploy tokens with `read_registry` for GitLab.
- Grant read-only pull permissions. For ECR: `ecr:GetAuthorizationToken`,
  `ecr:BatchGetImage`, `ecr:GetDownloadUrlForLayer`, `ecr:DescribeImages`,
  `ecr:ListImages`, `ecr:DescribeRepositories` (a tested policy file is tracked in #18).
- ShieldMon disables the ECR helper's on-disk token cache: tokens live only in memory.

## Examples

```sh
shieldmon scan docker.io/library/nginx:1.27
shieldmon scan public.ecr.aws/docker/library/alpine:3.20
shieldmon scan gcr.io/distroless/static-debian12:latest
shieldmon scan registry.access.redhat.com/ubi9/nodejs-20-minimal:latest
AWS_PROFILE=readonly shieldmon scan 123456789012.dkr.ecr.eu-west-1.amazonaws.com/team/api:prod
shieldmon scan europe-west1-docker.pkg.dev/my-project/apps/api:1.4.2     # after gcloud auth
```
