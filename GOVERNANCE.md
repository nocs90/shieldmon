# Governance

## Roles

- **Maintainers** (listed in `.github/CODEOWNERS`): merge rights, release, security
  response, roadmap. Decisions by lazy consensus; a maintainer's explicit `-1` with
  reasoning blocks a change until resolved.
- **Area reviewers**: trusted contributors owning an area (`area/*` label) through
  CODEOWNERS. Promoted by maintainers after sustained, quality contributions.
- **Contributors**: everyone who opens issues, PRs, reviews or docs.

## How decisions are made

1. Small changes: a PR with one maintainer approval and green quality gates.
2. Design changes (data model, lifecycle rules, extension interfaces, security posture):
   an ADR in `docs/adr/` reviewed in the PR; at least one maintainer approval and 72 hours
   for objections.
3. Roadmap changes: edit `ROADMAP.md` via PR; milestones mirror it on GitHub.

## Non-negotiables

The invariants in SPEC.md (I1–I7) and the security requirements (S1–S3) change only
through an ADR approved by all active maintainers.

## Releases

Semantic Versioning. Pre-1.0, minor versions may break configuration; breaking changes are
called out in release notes. Release process: `docs/processes/release.md`.
