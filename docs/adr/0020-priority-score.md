# 0020 — Priority score: severity, exploitation, fix and SLA clock, explained

- Status: accepted
- Date: 2026-10-29

## Context

- Severity alone overwhelms teams: hundreds of "high" findings, of which a few are exploited,
  fixable today, or about to breach the remediation deadline (F6, #22).
- Scores that nobody can explain are not trusted, and scores that change with the scanner or
  the day of the week cannot be audited.

## Decision

A deterministic score from 0 to 100, computed by the pure package `internal/priority`, always
shown with the reasons that make it up:

| Part | Points |
|---|---|
| Impact: CVSS base score × 4 (the severity stands in when CVSS is unknown: critical 9.5, high 7.5, medium 5, low 2.5, negligible 0.5, unknown 5) | 0–40 |
| Exploitation: in CISA KEV (ADR 0019) | 30 |
| … otherwise EPSS ≥ 50% / ≥ 10% / ≥ 1% | 20 / 15 / 8 |
| A fixed version is known (remediation is an upgrade) | 10 |
| SLA clock under the configured profile: deadline passed / within 7 days / within 30 days | 20 / 15 / 8 |

The total is capped at 100. The SLA part makes the score follow the organization's policy:
the same finding ranks higher under a stricter profile.

- `findings list --sort priority` orders by it (and `--limit` keeps the top N by priority);
  `findings list` shows it in every format.
- Reports carry it per row (`priority`, `priority_reasons` in JSON; a `priority` column in the
  remediation plan), computed as of the report's end.

## Consequences

- Exploited and fixable problems rise above merely severe ones; nothing is hidden: severity
  and state are unchanged, the score only orders.
- EPSS points depend on the EPSS value scanners report (grype today); an EPSS enricher would
  make it scanner-independent like KEV.
- Changing a weight is a design change: a new ADR, and reports state nothing about past
  scores (they are recomputed).
