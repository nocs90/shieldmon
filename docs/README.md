# ShieldMon documentation

Start here. New? [Try ShieldMon locally](getting-started.md) in 15 minutes, then
[test it by hand with Docker](manual-testing.md) on real multi-stage builds and your own Dockerfiles. Every process the project runs is written down; if you do something that is
not described, describe it (that is part of the change).

## Understand

| Document | What it answers |
|---|---|
| [SPEC.md](../SPEC.md) | What ShieldMon must do; invariants I1–I7; what is implemented |
| [ARCHITECTURE.md](../ARCHITECTURE.md) | C4 diagrams, pipeline, packages, data model |
| [THREAT_MODEL.md](../THREAT_MODEL.md) | STRIDE on ShieldMon itself, residual risks |
| [ROADMAP.md](../ROADMAP.md) | Milestones and their definition of done |
| [adr/](adr/) | Why things are the way they are, with evidence |

## Operate

| Process | Document |
|---|---|
| The monitoring cycle, step by step | [processes/monitoring-cycle.md](processes/monitoring-cycle.md) |
| Triage, decisions and the finding lifecycle | [processes/triage-and-decisions.md](processes/triage-and-decisions.md) |
| Remediation: how fixes are made and tracked (rebuilds, Renovate) | [processes/remediation.md](processes/remediation.md) |
| Registries and credentials (Docker Hub, ECR, GCR/Artifact Registry, …) | [processes/registries.md](processes/registries.md) |
| Monthly reporting (HTML, Markdown, CSV, JSON) | [processes/reporting.md](processes/reporting.md) |
| Responding to health findings | [processes/health-findings.md](processes/health-findings.md) |

## Contribute

| Process | Document |
|---|---|
| From issue to merged PR | [processes/contribution-workflow.md](processes/contribution-workflow.md) |
| Quality gates (what CI checks and how to run it locally) | [processes/quality-gates.md](processes/quality-gates.md) |
| Issues, labels, milestones and the Project board | [processes/issue-management.md](processes/issue-management.md) |
| Releases | [processes/release.md](processes/release.md) |
| Security response | [processes/security-response.md](processes/security-response.md) |
| Extending ShieldMon (adapters, formats, providers) | [extending/README.md](extending/README.md) |
