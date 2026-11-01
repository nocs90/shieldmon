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
| Deployment: systemd timer, Kubernetes CronJob | [processes/deployment.md](processes/deployment.md) |
| The monitoring cycle, step by step | [processes/monitoring-cycle.md](processes/monitoring-cycle.md) |
| Triage, decisions and the finding lifecycle | [processes/triage-and-decisions.md](processes/triage-and-decisions.md) |
| Remediation: how fixes are made and tracked (rebuilds, Renovate) | [processes/remediation.md](processes/remediation.md) |
| Expressing your remediation policy (deadlines, decision limits) | [processes/remediation-policy.md](processes/remediation-policy.md) |
| Enrichment (CISA KEV) | [processes/enrichment.md](processes/enrichment.md) |
| CI gate: pass, warn or fail an image on policy | [processes/ci-gate.md](processes/ci-gate.md) |
| Base images: rebuild available, unmaintained bases | [processes/base-images.md](processes/base-images.md) |
| Ownership: teams, their findings and their channels | [processes/ownership.md](processes/ownership.md) |
| Runtime context: which images run in a cluster, which are exposed | [processes/runtime-context.md](processes/runtime-context.md) |
| Images of Helm charts and Kubernetes manifests | [processes/manifest-images.md](processes/manifest-images.md) |
| Exports to Dependency-Track and DefectDojo | [processes/exports.md](processes/exports.md) |
| Notifications (webhook, e-mail, chat, issue trackers) | [processes/notifications.md](processes/notifications.md) |
| Registries and credentials (Docker Hub, ECR, GCR/Artifact Registry, …) | [processes/registries.md](processes/registries.md) |
| Monthly reporting (HTML, Markdown, CSV, JSON, remediation plan, SARIF) | [processes/reporting.md](processes/reporting.md) |
| Inventory: what is monitored and how fresh the evidence is | [processes/inventory.md](processes/inventory.md) |
| Tamper-evident audit trail: digests and verification | [processes/audit.md](processes/audit.md) |
| Responding to health findings | [processes/health-findings.md](processes/health-findings.md) |
| Running the container image | [README](../README.md#container-image), [adr/0012-container-image.md](adr/0012-container-image.md), [deploy/scratch](../deploy/scratch/README.md) |

## Contribute

| Process | Document |
|---|---|
| From issue to merged PR | [processes/contribution-workflow.md](processes/contribution-workflow.md) |
| Quality gates (what CI checks and how to run it locally) | [processes/quality-gates.md](processes/quality-gates.md) |
| Issues, labels, milestones and the Project board | [processes/issue-management.md](processes/issue-management.md) |
| Releases | [processes/release.md](processes/release.md) |
| Security response | [processes/security-response.md](processes/security-response.md) |
| Extending ShieldMon (adapters, formats, providers) | [extending/README.md](extending/README.md) |
