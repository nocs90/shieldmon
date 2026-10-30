# Monthly reporting

```sh
shieldmon report monthly --month 2026-10 -o html --out reports/2026-10.html  # self-contained summary for stakeholders
shieldmon report monthly --month 2026-10 -o md  --out reports/2026-10.md
shieldmon report monthly --month 2026-10 -o csv --out reports/2026-10.csv   # open and accepted findings, flat
shieldmon report monthly --month 2026-10 -o remediation-plan --out reports/2026-10-plan.csv
shieldmon report monthly --month 2026-10 -o remediation-plan-excel --out reports/2026-10-plan.csv  # BOM + CRLF for spreadsheets
shieldmon report monthly --month 2026-10 -o json --out reports/2026-10.json
shieldmon report monthly --month 2026-10 -o sarif --out reports/2026-10.sarif  # code-scanning dashboards
```

## SARIF

`sarif` writes SARIF 2.1.0 (validated against the OASIS schema in tests) for dashboards
that read it: one result per open finding, and risk acceptances as results with an
`accepted` suppression and their justification. Each vulnerability is a rule (with
`security-severity` from CVSS and a link to OSV); the location is the package URL, with the
package and the images as logical locations; `partialFingerprints` stay the same while the
problem persists across versions and digests, so dashboards do not count it again. Not
affected findings are not results.

## Remediation plan

`remediation-plan` is the worksheet auditors and compliance teams track: one row per open or
risk-accepted item as of the end of the month, soonest scheduled completion first.

| Column | Meaning |
|---|---|
| `item_id`, `status` | the finding and its lifecycle state |
| `weakness`, `aliases`, `weakness_description` | vulnerability ID, other IDs, title |
| `severity`, `cvss`, `epss`, `kev` | risk |
| `asset`, `digest`, `package`, `installed_version`, `purl` | where it is: targets resolving to the digest, and the package |
| `detected`, `age_days` | first detection (inherited across digests) |
| `sla_due`, `sla_breached` | remediation deadline from the policy ([remediation-policy.md](remediation-policy.md)) |
| `scheduled_completion` | the deadline, or for a risk acceptance its expiry (when it must be fixed or decided again) |
| `milestones` | dated steps (detected, due, decision expiry or vendor review), then the upgrade when a fix exists |
| `fix_available`, `fixed_versions` | `yes`, `no` or `wont_fix` (the vendor says it will not fix) |
| `priority` | remediation priority 0–100 as of the report ([ADR 0020](../adr/0020-priority-score.md)); `priority_reasons` in JSON |
| `deviation` | why it may outlive its deadline: `risk_acceptance`, `vendor_dependency`, `operational_requirement`; empty for open items |
| `remedy` | for images with a known base: `rebuild` (the newest base ships another version of the package), `base` (the newest base has the same version), `application` (the image's own layers), `unknown` ([base-images.md](base-images.md#what-a-rebuild-fixes)) |
| `decision`, `decision_author`, `decision_justification`, `decision_expires` | the latest decision on the finding |

Cells that a spreadsheet would read as formulas (`=`, `+`, `-`, `@`) are prefixed with `'`,
and every cell is on one line: package names and titles come from image content.
`remediation-plan-excel` has the same content with a UTF-8 byte order mark and CRLF line
endings, which spreadsheet applications need to show non-ASCII names correctly.

The report is computed from the append-only audit trail, so it can be regenerated for any
past month with identical results. Files are written 0600 (they are an inventory of
weaknesses).

| Metric | Definition |
|---|---|
| Open at start/end | findings whose state at that instant is open, reopened, triaged or in_remediation |
| Newly opened | new lineages first detected in the period (carry-overs to new digests are not new) |
| Fixed | transitions to `fixed` in the period (scan evidence) |
| MTTR | fixed time − inherited first detection, mean and median, for fixes in the period |
| Open past SLA | open findings older than the SLA for their severity (`sla.profile`) |
| Burndown | open count at end of each day |
| Monitoring health | open health findings: gaps in the evidence itself |
| Inventory changes | images added, rebuilt (new digest, with its scan), retired and restored in the period ([inventory.md](inventory.md#changes-over-a-period)) |
| Retired with the image | findings still open whose images were all retired (`targets retire`): not open, not fixed ([inventory.md](inventory.md#retiring-an-image)) |
| Base images | monitored targets on the newest base, with a rebuild available, with an unverified base, without a known base, and on an unmaintained base, at the end of the period; the targets needing action are listed ([base-images.md](base-images.md)) |

The current month is reported "as of now". Deadlines come from `sla.profile` and
`sla.days` in the configuration.
