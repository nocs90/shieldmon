# Expressing your remediation policy

ShieldMon measures remediation against **your** policy: deadlines per severity and limits on
decisions. Write them in the configuration; every command validates them at startup
([ADR 0016](../adr/0016-remediation-timeframes.md), [ADR 0010](../adr/0010-decision-policy.md)).

## 1. Pick the closest profile

| Profile | Critical | High | Medium | Low | Negligible |
|---|---:|---:|---:|---:|---:|
| `standard` (default) | 30 | 30 | 90 | 180 | — |
| `strict` | 15 | 30 | 90 | 180 | — |

Days from **first detection** of the problem, inherited when a new digest of the image still
has it. "—" is no deadline.

## 2. Override what differs

```yaml
sla:
  profile: standard
  days: { critical: 15, high: 30, medium: 60, low: 120, negligible: 365 }
```

Rules, checked at startup:

- 0 means no deadline; at most 3650 days;
- a more severe finding never gets more time than a less severe one: `critical ≤ high ≤
  medium ≤ low ≤ negligible` among those with a deadline, and if a severity has a deadline,
  every more severe one has one too.

Worked mappings:

| Your policy says | Configuration |
|---|---|
| "Critical and high within 30 days, the rest within 90" | `profile: standard`, `days: { medium: 90, low: 90 }` |
| "Critical in 7 days, high in 14, medium and low best effort" | `days: { critical: 7, high: 14, medium: 0, low: 0 }` |
| "Exposed systems: critical in 15 days" | `profile: strict` (in a configuration for those targets) |

ShieldMon keeps one policy per data directory: monitor targets under different policies
from different data directories.

## 3. Bound decisions

```yaml
decisions:
  vendor_dependency_max_days: 30         # no fix exists: reviewed at least this often
  operational_requirement_max_days: 365  # fix exists, cannot be applied: longest acceptance
```

A plain risk acceptance never outlives the deadline; beyond it a decision needs one of these
deviations (see [triage and decisions](triage-and-decisions.md)). The vendor dependency's
review period must not exceed the operational requirement's maximum.

## 4. Check the result

```sh
shieldmon --config policy.yaml findings list   # SLA DUE column per finding
shieldmon report monthly -o md                 # the report names the profile it used
```

An incoherent policy stops every command with the two severities in conflict, for example:

```
sla: critical deadline (60 days) is longer than high (30 days): a more severe finding cannot get more time
```

Deadlines are computed, not stored: changing the policy changes them for every finding,
past ones included, in the next report.
