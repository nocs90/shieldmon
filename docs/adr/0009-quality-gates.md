# 0009 — Quality gates

- Status: accepted
- Date: 2026-10-20

## Context

ShieldMon is a security tool processing hostile input with credentials; contributions
must be easy to make and hard to get wrong. In this repository, fuzzing found a real
non-idempotent PURL canonicalization bug within seconds, and a unit test found that the
scanner output limit was silently bypassed (`bytes.Buffer.ReadFrom` promoted through
embedding). Both would have corrupted deduplication or allowed unbounded memory use.

## Decision

Required gates on `main` (docs/processes/quality-gates.md): formatting (gofmt/gofumpt),
vet, golangci-lint with gosec/errcheck/revive/errorlint/nolintlint, tidy check, race
tests, a coverage floor that only goes up (start 50%), govulncheck, fuzzing of every
hostile-input parser, CodeQL, gitleaks, dependency review (vulnerabilities and
AGPL-incompatible licenses), Conventional PR titles, DCO. Integration tests with real
scanners run on main, nightly and on labelled PRs. Scorecard is tracked. All actions are
pinned by commit SHA; Renovate proposes updates after a 14-day minimum release age.

## Consequences

- Contributors get the same checks locally via `make`.
- Every `//nolint` carries a linter name and a reason; exclusions are scoped and explained
  in `.golangci.yml`.
- CI time grows; fuzzing is short on PRs (20s/target) and long nightly (5m/target).
