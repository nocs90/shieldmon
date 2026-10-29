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

## What to look at first

```sh
shieldmon findings list --sort priority --limit 20
shieldmon findings list --sort priority -o json   # with the reasons behind each score
```

The priority (0–100) adds impact (CVSS), exploitation (CISA KEV, else EPSS), whether a fix
exists, and how close the remediation deadline of your SLA profile is
([ADR 0020](../adr/0020-priority-score.md)). It orders work; it never changes a finding's
severity or state.

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

## VEX statements

A vendor or another team saying "not affected" sends a VEX document (OpenVEX or CycloneDX
VEX). Review it, then import it ([ADR 0014](../adr/0014-vex.md)):

```sh
shieldmon vex import vendor.openvex.json --dry-run     # what would be recorded, what is skipped and why
shieldmon vex import vendor.openvex.json               # record; --author if the document names none
```

- Only `not_affected` statements with an author and a justification (or impact statement)
  are recorded; expired ones, and other statuses, are listed as skipped.
- A statement is scoped to an image digest, or to a whole repository, and optionally to one
  package (any version when the PURL has none). It becomes a not_affected decision by its
  author on matching findings — now, and on findings later scans detect. Statements for
  images not scanned yet are kept and reported.
- It ends at its expiry; there is no other way to withdraw it, so review before importing.

To give consumers and auditors ShieldMon's not_affected decisions:

```sh
shieldmon vex export --author "Platform Security <sec@example.com>" -o shieldmon.openvex.json
```

The export holds the statements in force and the not_affected decisions taken by hand, as
OpenVEX 0.2.0; risk acceptances are not VEX and are not exported.

## What the engine does on its own

| Observation | Transition |
|---|---|
| Vulnerability absent from the successor digest (complete scan) | → fixed |
| Still present in successor digest | predecessor → superseded; successor inherits state, decision and first-detection date |
| Gone from the same digest after a DB update (complete scan) | → withdrawn (not counted as a fix) |
| Seen again / regression / decision expired | → reopened |
| New finding matched by a VEX statement in force | → not_affected (decision by the statement's author) |
| Partial scan (a matcher failed) | nothing is closed |
