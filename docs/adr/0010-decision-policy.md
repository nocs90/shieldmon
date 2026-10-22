# 0010 — Decision policy: remediation deadlines and deviations

- Status: accepted
- Date: 2026-10-21

## Context

A risk acceptance with an arbitrary expiry lets a team silently extend the remediation
deadline, which defeats SLA tracking and is not acceptable in regulated environments.
Common security policies set remediation timeframes by severity, counted from detection
(for example: critical and high 30 days, medium 90, low 180). Findings that cannot meet
them are handled as documented *deviations* (false positive, operational requirement,
risk adjustment) or tracked as *vendor dependencies* when no fix exists. Scanners report whether a fix exists: grype `fix.state`
(`fixed`, `not-fixed`, `wont-fix`), trivy `Status` (`fixed`, `affected`, `will_not_fix`,
`fix_deferred`, `end_of_life`…).

## Decision

- Store a normalized `fix_state` per finding: `fixed`, `not_fixed`, `wont_fix`, `unknown`
  (any scanner knowing a fix wins).
- SLA profiles: `standard` (default: critical/high 30, medium 90, low 180 days) and
  `strict` (critical 15, high 30, medium 90, low 180), with per-severity overrides
  (`sla.days`) so that any organizational policy can be expressed. Deadline = first detection (inherited across digests) + days.
- `risk_accepted` decisions:
  - **no deviation**: expiry required and ≤ the deadline (default: the deadline); refused
    once the deadline has passed;
  - **vendor_dependency**: only when no fix is known; expiry ≤ now + 30 days (renewable,
    "monthly vendor check"); the engine **reopens** it as soon as a fix appears;
  - **operational_requirement**: fix exists but cannot be applied; justification ≥ 40
    characters; explicit expiry ≤ now + 365 days.
- False positives are VEX `not_affected` statements, not deviations.
- Limits are configurable (`decisions.*`); deviations are recorded on the decision and shown
  in reports (and later in the remediation-plan export).


## Consequences

- SLA breach numbers can be trusted: acceptances cannot hide overdue findings.
- "Won't fix" OS packages from vendors such as Red Hat get a documented, reviewable path
  instead of a permanent suppression.
