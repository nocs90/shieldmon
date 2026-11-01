# 0016 — Remediation timeframes: defaults, overrides and coherence

- Status: accepted
- Date: 2026-10-28

## Context

- Remediation deadlines encode an organization's security policy. ShieldMon measures
  against them (SLA due date, breaches, MTTR in reports) and bounds risk acceptances by
  them (ADR 0010), so a wrong deadline silently weakens every number built on it.
- Common security policies and public remediation directives set timeframes by severity,
  counted from detection: 30 days for critical and high, 90 for medium, 180 for low are
  frequent; stricter regimes give 15 days to critical findings on exposed systems.
- Configuration mistakes happen: a critical deadline longer than the high one, a typo
  adding a zero, a severity left without a deadline. They were accepted until now.

## Decision

1. **Profiles.** `standard` (default): critical 30, high 30, medium 90, low 180 days;
   `strict`: critical 15, high 30, medium 90, low 180. Negligible and unknown severities
   have no deadline unless configured. Per-severity overrides (`sla.days`, critical to
   negligible) express any other policy on top of a profile.
2. **Counted from first detection**, inherited across digests of a target (the problem, not
   the image, has the deadline), as before.
3. **Coherence, checked at startup** (every command loads the configuration):
   - each deadline 0 (none) to 3650 days;
   - a more severe finding never gets more time than a less severe one, nor no deadline while
     a less severe one has one;
   - decision limits positive, at most 3650 days, and a vendor dependency's review period no
     longer than the longest operational requirement.
4. Unknown profile or severity names are errors, never silently ignored.

## Consequences

- A policy that cannot be expressed coherently fails loudly, before any report is built on it.
- Configurations that relied on incoherent deadlines must be fixed when upgrading; the error
  names the two severities in conflict.
- Changing the policy changes deadlines retroactively (they are computed, not stored):
  reports state the profile they used.
