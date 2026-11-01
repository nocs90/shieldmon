# 0017 — Target retirement: an asset event, not a fix

- Status: accepted
- Date: 2026-10-28

## Context

- Images are decommissioned. ShieldMon had no way to stop monitoring one: its tag kept being
  resolved every cycle, its open findings kept counting in reports, SLA breaches and
  notifications, and the inventory listed it as monitored (#72).
- Closing those findings would be wrong: nothing proved them fixed. Only scan evidence or a
  decision closes a finding (I4), and only `lifecycle.Reconcile` sets `fixed`, `superseded`
  or `withdrawn`.
- Vulnerability management tools treat a decommissioned asset as out of scope: its findings
  stop counting, their history stays, and they come back if the asset does.

## Decision

1. **Retirement is recorded on the target, append-only**: `target_events` (retire or
   restore, actor, reason, time). `shieldmon targets retire|restore TARGET --by --reason`.
   A target is retired when its latest event is a retirement.
2. **Finding states never change because of it.** No event is written on findings; MTTR and
   fix counts are untouched.
3. **Scope is derived.** A finding is *retired with its asset* at time T when every target
   whose digest at T (from the append-only digest history) is the finding's digest was
   retired at T. A digest still used by an active target keeps its findings in scope.
4. Out of scope findings are excluded from open counts, burndown, SLA breaches, the
   inventory's open counts and notifications; reports show them apart ("retired with the
   asset"). The inventory lists retired images with their retirement.
5. `monitor` skips retired targets; `scan` of a retired target is refused (restore it
   first); health findings about the target are resolved at retirement, since nothing will
   check them again.
6. **Restoring** a target puts its findings back in scope as they are; the next cycle
   resolves the tag and reconciles them with scan evidence as usual.

## Consequences

- Reports for past months are reproducible: scope at any instant comes from append-only
  history.
- A finding retired with its asset keeps its state (often `open`): queries on findings
  (`findings list`) still show it, flagged by its target's retirement; reports and
  notifications do not count it.
- Retiring is reversible and leaves no trace on the findings, so it cannot be used to hide a
  fix that never happened: the vulnerability is still there if the image comes back.
