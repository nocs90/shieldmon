# IAM for ShieldMon on Amazon ECR

ShieldMon only reads images: it never pushes, deletes or changes anything in ECR.
`shieldmon-readonly.json` is the whole permission set; `internal/oci/iam_test.go` fails if it
grants anything the `ecr` provider does not call.

| Action | Used for |
|---|---|
| `ecr:GetAuthorizationToken` | pull token (resource `*` by AWS design) |
| `ecr:BatchGetImage` | manifests |
| `ecr:GetDownloadUrlForLayer` | layers |
| `ecr:DescribeImages` | tags with push times (`targets add-repo --latest N`) |
| `ecr:DescribeRepositories` | repository listing |

`ecr:ListImages` is not needed: `DescribeImages` lists tags and says when they were pushed.

Narrow the second statement's `Resource` to the repositories ShieldMon monitors, for example
`arn:aws:ecr:eu-west-1:123456789012:repository/team/*`.

## Who may assume the role

Only short-lived credentials: pick the trust policy for where ShieldMon runs and replace the
`<…>` placeholders. Federated principals are always pinned by `aud` and `sub`.

| ShieldMon runs in | Trust policy | Notes |
|---|---|---|
| GitHub Actions | `trust-github-oidc.json` | `aws-actions/configure-aws-credentials` with `role-to-assume`; `permissions: id-token: write` |
| GitLab CI | `trust-gitlab-oidc.json` | `id_tokens: { AWS_ID_TOKEN: { aud: https://gitlab.com } }`, then `AWS_ROLE_ARN` and `AWS_WEB_IDENTITY_TOKEN_FILE` |
| EKS, IRSA | `trust-eks-irsa.json` | service account annotated with `eks.amazonaws.com/role-arn` |
| EKS, Pod Identity | `trust-eks-pod-identity.json` | a Pod Identity association for the service account |
| Another account | `trust-cross-account.json` | in the account that owns the registry; ShieldMon assumes it with `role_arn` (and `external_id`) in `registries:` (docs/processes/registries.md) |
