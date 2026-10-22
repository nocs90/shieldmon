# Issues, labels, milestones and the Project board

The backlog lives in the repo (`.github/backlog/backlog.json`) and is published with
`scripts/github/bootstrap.py` (dry-run by default; `--apply` publishes; `--project` fills
the **ShieldMon Roadmap** Project). Re-running is idempotent.

## Labels

| Family | Values | Rule |
|---|---|---|
| `kind/*` | bug, feature, adapter, epic, chore, docs, dependency, test | exactly one |
| `area/*` | scanner, registry, lifecycle, storage, report, cli, engine, helm, vex, notify, enrich, packaging, release, ci, compliance, remediation, server | one or more; maps to CODEOWNERS |
| `priority/*` | critical, high, medium, low | set at triage |
| process | `needs-triage`, `blocked`, `run/integration` | |
| community | `good first issue`, `help wanted` | newcomer-friendly / maintainer wants help |
| `security` | | changes that touch the threat model (never for vulnerability reports: those are private) |

## Epics and milestones

- One **epic** (`kind/epic`) per open SPEC requirement (F*/S*); tasks reference it with
  "Part of #N". Epics close when all tasks close and SPEC's status column is updated.
- One **milestone** per ROADMAP milestone; a milestone closes when its definition of done
  passes in CI.

## Triage (weekly)

1. Every `needs-triage` issue gets kind/area/priority, a milestone (or "no milestone" =
   icebox), and the label removed.
2. Bugs affecting finding closure or the audit trail are `priority/high` at least.
3. Suspected vulnerabilities reported publicly: hide/convert to a private advisory
   (security-response.md).

## Project board

Columns: Todo → In progress → In review → Done. Group by milestone; filter by `area/*`.
Cards move automatically on PR open/merge (Project workflows).
