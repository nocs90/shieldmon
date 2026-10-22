# Triage, decisions and the finding lifecycle

Normative rules: [ADR 0004](../adr/0004-finding-lifecycle.md). This page is the runbook.

## Daily triage (≈10 minutes)

1. `shieldmon health` — fix pipeline problems first: a stale DB or a failed matcher means
   today's data is incomplete.
2. `shieldmon findings list --state open --state reopened --severity high`
3. For each finding: `shieldmon findings show ID` (details, fix versions, audit trail), then
   one of:

| Situation | Command | Result |
|---|---|---|
| Real, will be fixed | `findings triage ID --note "…"` then `findings remediate ID` when work starts | triaged → in_remediation |
| Not exploitable in this image (VEX) | `findings not-affected ID --author A --justification vulnerable_code_not_in_execute_path` | not_affected |
| Real, cannot fix in time, risk owned | `findings accept-risk ID --author A --justification "…"` | risk_accepted until the SLA deadline (or an earlier `--expires`) |
| Vendor will not fix / no fix exists ("won't fix") | `findings accept-risk ID --deviation vendor-dependency --author A --justification "…"` | risk_accepted for 30 days (renew monthly); **reopens automatically when a fix ships** |
| Fix exists but cannot be applied (e.g. breaks a FIPS module) | `findings accept-risk ID --deviation operational-requirement --expires YYYY-MM-DD --author A --justification "<detailed reason>"` | risk_accepted up to 365 days |
| Wrongly triaged | `findings untriage ID` | open |

There is **no** command to close a finding. Ship the fix (rebuild the image, move the
tag); the next cycle proves it and records the evidence scan.

## Decision rules

Remediation deadlines come from `sla.profile` (default `standard`: critical and
high 30 days, medium 90, low 180, from first detection — `findings list` shows them in
the SLA DUE column). A plain risk acceptance **cannot outlive the deadline**; going beyond
it needs a deviation, recorded on the decision and shown in reports
([ADR 0010](../adr/0010-decision-policy.md)).

- Justification ≥ 10 characters (≥ 40 for an operational requirement); for not-affected prefer the OpenVEX justification
  vocabulary (`component_not_present`, `vulnerable_code_not_present`,
  `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`,
  `inline_mitigations_already_exist`).
- Risk acceptance always expires; renew by issuing a new decision before expiry. A
  vendor dependency is refused when a fixed version is known: upgrade instead.
- Decisions follow the problem to successor digests (same package + vulnerability).

## What the engine does on its own

| Observation | Transition |
|---|---|
| Vulnerability absent from the successor digest (complete scan) | → fixed |
| Still present in successor digest | predecessor → superseded; successor inherits state, decision and first-detection date |
| Gone from the same digest after a DB update (complete scan) | → withdrawn (not counted as a fix) |
| Seen again / regression / decision expired | → reopened |
| Partial scan (a matcher failed) | nothing is closed |
