# Quality gates

Every gate runs in CI and can be run locally. Required checks on `main` are marked ✱.

| Gate | Local | CI job | Fails when |
|---|---|---|---|
| ✱ Formatting (gofmt + gofumpt/goimports) | `make fmt-check`, `golangci-lint fmt` | ci/lint | any file not formatted |
| ✱ go vet (incl. integration tag) | `make vet` | ci/lint | vet finding |
| ✱ golangci-lint (errcheck, gosec, revive, staticcheck, errorlint, bodyclose, nolintlint…) | `make golangci` | ci/lint | any issue; every `//nolint` must name a linter and a reason |
| ✱ go.mod tidy | `make tidy-check` | ci/lint | go.mod/go.sum drift |
| ✱ Unit tests with race detector | `make test-race` | ci/test | any failure |
| ✱ Coverage floor | `make cover` | ci/test | total < `COVER_MIN` (only ever raised) |
| ✱ govulncheck | `make vuln` | ci/test | reachable known vulnerability in our deps |
| ✱ Fuzzing of hostile-input parsers | `make fuzz` | ci/fuzz (20s/target on PR, 5m nightly) | crash or invariant violation; failing inputs are committed under `testdata/fuzz` as regressions |
| Integration (real syft/grype/trivy, pinned digest) | `make test-integration` | ci/integration (main, nightly, PRs labelled `run/integration`) | pipeline regression |
| Conformance kit for adapters | part of unit tests | ci/test | an adapter violates its contract |
| ✱ Scanner sandbox (bubblewrap, Linux) | `SHIELDMON_TEST_SANDBOX=bwrap go test -run TestBwrapSandbox ./internal/scanner` | ci/test | a sandboxed process reads, writes or sees outside its policy, or bwrap cannot start on the runner |
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
