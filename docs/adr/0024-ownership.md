# 0024 — Ownership: teams own targets by reference patterns in the configuration

- Status: accepted
- Date: 2026-10-30

## Context

- A deadline without an owner is nobody's deadline: remediation plans (POA&M) have a point of
  contact per item, and DefectDojo or Kondukto route findings per product team (#26).
- Organizations name images by team: `registry.example.com/payments/*`, a GitLab group, an
  ECR repository prefix. Hundreds of targets come and go (`targets add-repo`, CI): assigning
  each by hand would leave the new ones unowned.
- Every notification channel today receives every event; a team channel should hear only
  about its images, while the security team keeps hearing everything.

## Decision

- **Owners in the configuration**, a list of teams in order:

  ```yaml
  owners:
    - team: payments
      contact: payments-security@example.com
      targets: ["registry.example.com/payments/*", "ghcr.io/example/checkout"]
  ```

  A target belongs to the **first** team with a pattern matching its reference
  (`registry.example.com/payments/api:1.4`) or its repository (`…/payments/api`), with
  `path.Match` syntax (`*` within one path segment). Patterns without wildcards are normalized
  like references (`nginx` is `index.docker.io/library/nginx`). A target no rule matches is
  unowned and shown as such, never hidden. Team names, patterns and contacts are validated at
  startup.
- **Reports**: the owner of each row and target, a summary per owner (open by severity, past
  deadline, KEV, unowned included), an `owner` column in the remediation plan (team and
  contact); `findings list --owner TEAM` (`--owner -` for unowned); `targets list` shows it.
- **Notifications**: a channel with `owners: [team…]` receives only the finding and base events
  of those teams' targets, and no health events; channels without `owners` are unchanged.
  Owners are resolved when sending, from the configuration of that moment.
- Ownership changes no finding, decision or deadline.

## Consequences

- Ownership follows the configuration's version control and review, like the rest of the
  policy; new targets are owned from their first cycle.
- Reports use the ownership configured when they are generated, not the one of the period
  they cover: regenerating a past month after a reorganization shows today's teams. The JSON
  report carries the owners it used.
- A target matching several teams belongs to the first: order the list from specific to
  general.
