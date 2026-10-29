# 0021 — Policy gate: decide a pipeline on policy, fail closed, exempt only by decision

- Status: accepted
- Date: 2026-10-29

## Context

- Reports tell people what is wrong after the fact; a pipeline needs a yes or no before an
  image ships (#27, ROADMAP M4). Scanners offer thresholds (`grype --fail-on high`,
  `trivy --exit-code 1 --severity CRITICAL`), and Anchore Enterprise evaluates policy
  bundles with stop/warn actions. A severity threshold alone fails on problems nobody can
  fix and passes exploited ones that are "only" high.
- The usual way out of a failing threshold is an ignore list in the repository
  (`.trivyignore`, grype `ignore:`): exemptions without an author, a justification or an
  expiry, invisible to the people who own the risk. ShieldMon already has auditable
  exemptions: decisions with an author, a justification and an expiry (ADR 0010) and VEX
  statements (ADR 0014).
- A gate that passes because a matcher failed, or because its vulnerability DB is weeks
  old, passes by accident. When one matcher fails the engine records a `partial` scan with
  the other matcher's findings only: fewer findings, not fewer problems (that is why a
  partial scan never closes a finding, ADR 0004).
- CI systems tell apart outcomes by exit code: GitLab `allow_failure: exit_codes` turns
  one code into a warning; grype uses 1 for errors and 2 for a `--fail-on` violation.

## Decision

`shieldmon gate IMAGE` evaluates the findings of the image's digest against a policy and
ends with a verdict: `pass`, `warn`, `fail` or `indeterminate`.

- **Evidence.** By default the gate scans the image like `shieldmon scan` (the image becomes
  a target; an ephemeral data dir keeps a CI job's images out of the monitoring inventory).
  `--no-scan` evaluates the stored evidence of an image already scanned, without registries
  or scanners.
- **Policy** (`gate:` in the configuration, or `--policy FILE` with the same schema, unknown
  keys refused): rules with an action (`fail` or `warn`) and conditions under `when`, which
  must all hold: minimum `severity`, `cvss`, `epss`, `priority` (ADR 0020), `age_days` (from
  the inherited first detection), and `kev`, `fixable`, `sla_breached` (under the configured
  SLA profile). `when: {}` matches every finding. A finding is flagged by the strongest
  action of the rules it matches. Without a configured policy a built-in one applies: fail
  on KEV, on critical, on a breached deadline; warn on high.
- **Exemptions only by decision.** A finding is exempt when its state is in `exempt`
  (default `[not_affected, risk_accepted]`) and its decision has not expired at evaluation
  time. The policy has no ignore list by vulnerability or package: an exemption needs an
  author, a justification and an expiry, recorded in the audit trail. Exempt findings are
  reported with their decision.
- **Fail closed.** With no violation, the verdict is `indeterminate` when the evidence cannot
  prove a pass: the scan is not complete, a matcher's DB is older than `max_db_age` (default
  the configured `health.db_max_age`), or, with `--no-scan`, there is no scan or the latest is
  older than `max_evidence_age` (default 24h). Violations found in partial evidence fail: what
  was seen is real.
- **Exit codes:** 0 pass, 0 warn, 2 fail, 3 indeterminate, 1 error (usage, resolution,
  storage). `exit_codes` in the policy changes `warn`, `fail` and `indeterminate` (0–125;
  `fail` and `indeterminate` never 0).
- **Output:** a table, JSON, or SARIF 2.1.0 sharing rules and fingerprints with the monthly
  SARIF report: violations as results (`error` for fail, `warning` for warn), exemptions as
  suppressed results with their justification.
- The gate changes no finding state and records nothing beyond the scan it runs.

## Consequences

- A team that disagrees with the gate records a decision, which the monthly report,
  `vex export` and auditors see; a vendor statement imported as VEX unblocks every image of
  the repository at once.
- A gate in an ephemeral CI job sees only its own decisions: VEX documents imported in the
  job (`shieldmon vex import`), not risk acceptances taken on the monitoring instance.
- The policy belongs to whoever owns the risk: kept in the configuration of the monitoring
  instance, or in a file the gated repository cannot change.
- Gate verdicts are not stored: the CI log and the SARIF artifact are the record. Storing
  them would need its own audited table.
