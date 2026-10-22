# 0004 — Finding lifecycle and evidence-based closure

- Status: accepted
- Date: 2026-10-20

## Context

Findings are keyed by (digest, PURL, vulnerability). Digests are immutable, so a
vulnerability is "fixed" only when the *target* (a tag) moves to a successor digest that
no longer contains it. The original state list (open → triaged → in_remediation → fixed |
risk_accepted | not_affected → reopened) does not say what happens to a finding on the
old digest when the successor still contains the same vulnerability (typically after a
partial package bump), nor when an advisory is withdrawn from the vulnerability DB.
Marking either as `fixed` would inflate fix counts and understate MTTR.

## Decision

States: `open`, `triaged`, `in_remediation`, `reopened`, `risk_accepted`,
`not_affected`, `fixed`, `superseded`, `withdrawn`.

- **Lineage key** = (PURL without version, vulnerability ID) across the digests a target
  has pointed to.
- Successor contains the lineage key → new finding on the successor **inherits**
  `first_detected_at`, state and any decision; predecessor → `superseded`. Positive
  evidence, so allowed from a partial scan.
- Successor lacks it → predecessor → `fixed`, evidence = the successor scan. Requires a
  **complete** scan (every configured matcher succeeded).
- Same digest no longer reports it → `withdrawn` (complete scan only). Not a fix.
- Re-detection of a terminal finding, a lineage previously `fixed` in the target's history
  (regression), or an expired decision → `reopened`.
- Predecessors still current for *another* target are not closed.
- Humans may move only between open/reopened/triaged/in_remediation.
  `risk_accepted` requires justification, author and expiry; `not_affected` requires
  justification and author. Decisions are append-only; the latest governs expiry.
- Every transition is an append-only event with actor, reason and evidence scan.

## Consequences

- MTTR is measured on the problem, not the rebuild; superseded/withdrawn are reported
  separately and never counted as fixes.
- The planner (`internal/lifecycle`) is pure and exhaustively unit-tested; the store
  applies plans transactionally with optimistic state checks.
- VEX import/export (M4) maps onto decisions.
