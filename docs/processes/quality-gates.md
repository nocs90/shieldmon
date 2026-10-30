# Quality gates

Every gate runs in CI and can be run locally. Required checks on `main` are marked ✱.

| Gate | Local | CI job | Fails when |
|---|---|---|---|
| ✱ Formatting (gofmt + gofumpt/goimports) | `make fmt-check`, `golangci-lint fmt` | ci/lint | any file not formatted |
| ✱ go vet (incl. integration tag) | `make vet` | ci/lint | vet finding |
| ✱ golangci-lint (errcheck, gosec, revive, staticcheck, errorlint, bodyclose, nolintlint…) | `make golangci` | ci/lint | any issue; every `//nolint` must name a linter and a reason |
| ✱ go.mod tidy | `make tidy-check` | ci/lint | go.mod/go.sum drift |
| ✱ Unit tests with race detector | `make test-race` | ci/test | any failure |
| ✱ Coverage floor | `make cover` | ci/test | total < `COVER_MIN` (70%, only ever raised); statements run by any test count (`-coverpkg=./...`), so end-to-end scenarios count for the packages they exercise |
| ✱ govulncheck | `make vuln` | ci/test | reachable known vulnerability in our deps |
| ✱ Fuzzing of hostile-input parsers | `make fuzz` | ci/fuzz (20s/target on PR, 5m nightly) | crash or invariant violation; failing inputs are committed under `testdata/fuzz` as regressions. Minimization is bounded (`FUZZMINIMIZE=100x`): with realistic seeds the default 60s per new input left targets almost no executions |
| Integration (real syft/grype/trivy, pinned digest) and hostile fixture suite, in the default sandbox | `make test-integration` (`SHIELDMON_TEST_SANDBOX=bwrap` to fail where no sandbox runs) | ci/integration (main, nightly, PRs labelled `run/integration`) | pipeline regression; a 10,000-layer manifest, a layer over the size limit, a decompression bomb, a path or symlink escape, or a hanging scanner that does not end bounded with its health finding, or leaves files outside the image or in the scratch space |
| Conformance kit for adapters | part of unit tests | ci/test | an adapter violates its contract |
| ✱ Scanner sandbox (bubblewrap and Landlock, Linux) | on Ubuntu ≥ 23.10 load an AppArmor profile for bwrap first (`deploy/apparmor/README.md`); `SHIELDMON_TEST_SANDBOX=bwrap,landlock go test -run 'TestBwrapSandbox\|TestSandboxBackendsConform' ./internal/scanner` | ci/test | a sandboxed process reads, writes, connects or sees outside its policy, escapes the seccomp filter, outlives its timeout, or a backend cannot run on the runner |
| ✱ Scanner sandbox under AppArmor's `bwrap-userns-restrict` | load that profile instead (`deploy/apparmor/README.md`); `SHIELDMON_TEST_SANDBOX=bwrap go test -run '^(TestSandboxBackendsConform\|TestBwrapSandbox)$/^bwrap$' ./internal/scanner` | ci/sandbox-apparmor-restrict | the profile recommended for shared hosts breaks the bwrap backend |
| ECR provider against a sandbox account | `SHIELDMON_TEST_ECR_REPO=… go test -tags integration -run TestECRIntegration ./internal/oci` with AWS credentials | ci/ecr (GitHub OIDC, no static keys; skipped until the `SHIELDMON_ECR_*` repository variables are set) | listing or pulling through the provider fails |
| GitLab provider against a real project | `SHIELDMON_TEST_GITLAB_REPO=… go test -tags integration -run TestGitLabIntegration ./internal/oci` with a deploy token and a read_api token | ci/gitlab (skipped until `SHIELDMON_GITLAB_REPO` and the GitLab secrets are set) | listing or pulling through the provider fails |
| ✱ Container image (linux/amd64, linux/arm64) | `make image`; `python3 scripts/check-image.py CRANE IMAGE` | ci/image (build, checks and smoke test always; scans on main, nightly, PRs labelled `run/integration`) | the Dockerfile does not build for both platforms; the image is not non-root, has another entrypoint or `TMPDIR`, or lacks a static binary of the right architecture; it does not start read-only without capabilities, or `landlock` is not available in it; a scan run by the container, or of the image, does not complete |
| ✱ CodeQL (security-extended) | — | security/codeql (public repo only) | new alert |
| ✱ Secret scanning (gitleaks, `.gitleaks.toml`) | `gitleaks detect` | security/secrets | secret in history; synthetic test credentials are allowlisted by path only |
| ✱ Dependency review | — | security/dependency-review (PR, public repo only) | vulnerable (≥ moderate) or AGPL-incompatible dependency |
| OpenSSF Scorecard | — | scorecard (public repo only) | tracked, not blocking |
| ✱ Conventional PR title | — | pr-hygiene | title format |
| ✱ DCO sign-off | `git log` | pr-hygiene | a commit lacks `Signed-off-by` |
| Supply chain pinning | review | review | actions not pinned by SHA, scanners not pinned by checksum |

## Repository settings (maintainer checklist)

- Branch protection on `main`: PR required, 1 approval, CODEOWNERS review, dismiss stale
  approvals, required status checks = the ✱ rows, linear history, no force pushes.
- Enable: private vulnerability reporting, Dependabot alerts, secret scanning + push
  protection, Discussions.
- Install the Renovate app (config in `renovate.json`; 14-day minimum release age).
