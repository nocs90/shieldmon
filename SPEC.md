# ShieldMon — Specification

ShieldMon automates container vulnerability **continuous monitoring (ConMon)** end to end:
scan → SBOM → tracked findings → remediation proposals → evidence-based closure →
month-by-month lifecycle reporting. It replaces manual spreadsheet work by security and compliance teams and
fragmented multi-team hand-offs. Remediation deadlines and reporting are
configurable to an organization's own security policy.

Licensed AGPL-3.0. Every dependency and every integrated scanner must be free software.

Status legend: ✅ implemented (M1) · 🟡 partial · ⬜ planned (see [ROADMAP.md](ROADMAP.md)).

## Core invariants

These are not features; violating one is a bug.

| # | Invariant | Where enforced |
|---|---|---|
| I1 | The identity of what was scanned is the **platform manifest digest**, never a tag. Tags are resolved on every cycle. | `internal/oci`, `targets`/`target_digests` |
| I2 | A finding's key is **(digest, canonical PURL, canonical vulnerability ID)**. | `findings` UNIQUE constraint |
| I3 | SBOMs are generated **once per (digest, generator)** and re-matched afterwards without pulling the image. | `engine.ensureSBOMs` |
| I4 | A finding is closed **only by scan evidence** (absence in a *complete* scan) or by a **decision** with justification, author and (for risk acceptance) expiry. No click-to-close. | `lifecycle`, `store.Transition` |
| I5 | Scan history and state changes are **append-only**, and **tamper-evident**: hash-chained, verified on schedule, anchored by exported digests. | SQLite triggers, `audit_chain` (ADR 0018) |
| I6 | Failures of the monitoring process itself are **findings** (self-health). | `health_findings` |
| I7 | Image content, SBOMs, scanner output and registry responses are **hostile input**. | see [THREAT_MODEL.md](THREAT_MODEL.md) |

## Functional requirements

| ID | Requirement | Status |
|---|---|---|
| F1 | Input: image ref (tag or digest). Always resolve to digest; multi-arch indexes resolve to the configured platform. | ✅ refs, image list files, registry repositories and paths with tag filters and latest-N (`targets add`, `targets add-repo`); retirement of decommissioned images (`targets retire`/`restore`, ADR 0017) · ⬜ Helm charts |
| F2 | Pluggable scanner adapters (Grype, Trivy) behind one interface and a plugin registry with a conformance kit; normalize; dedupe across scanners and aliases (CVE/GHSA/distro); record scanner name, version, DB version and DB age on every scan. | ✅ |
| F3 | SBOM-first: generate once per digest (CycloneDX + SPDX), store, re-match on schedule without re-pulling. | ✅ (syft: CycloneDX + SPDX; trivy: CycloneDX) |
| F4 | Storage: SQLite (CLI/single node) and PostgreSQL (server), same schema, versioned migrations, append-only history. | ✅ SQLite · ⬜ PostgreSQL |
| F5 | Lifecycle state machine with evidence-based closure; VEX decisions; OpenVEX / CycloneDX VEX import/export. | ✅ state machine + decisions with policy deviations (ADR 0010); VEX statements scoped by digest/repository/PURL, OpenVEX and CycloneDX VEX import, OpenVEX export (ADR 0014) |
| F6 | Prioritization: CVSS + EPSS + CISA KEV + fix availability; SLA profiles; aging and SLA-breach tracking. | 🟡 data captured; SLA profiles (`standard` default, configurable) enforced on risk acceptance; vendor fix state (won't fix); aging; CISA KEV catalog enricher, refreshed with the DBs and applied on every scan (ADR 0019); priority score with reasons (CVSS, KEV/EPSS, fix, SLA clock; ADR 0020) in `findings list --sort priority` and reports; policy gate for CI (`shieldmon gate`: rules on severity, CVSS, EPSS, KEV, priority, age, fix, SLA; exemptions only by decision; fails closed on incomplete evidence; exit codes and SARIF; ADR 0021) |
| F7 | Remediation proposals: fixed-in versions, base-image upgrade candidates, Copacetic patching, MR/PR drafts — never pushed without human approval. | 🟡 fixed-in versions; base image lineage (configured or annotated base proven by shared layers; current, rebuild available, unmaintained; ADR 0022); per finding, whether a rebuild on the newest base replaces the package, the base has the same version, or it is the application's (ADR 0023); configured successor bases, followed for freshness (ADR 0025) · ⬜ rest |
| F8 | Reporting: monthly lifecycle (opened, closed, MTTR, burndown, SLA breaches, accepted-risk aging) as JSON, CSV, Markdown/HTML, SARIF; remediation-plan and inventory exports for audits. | ✅ JSON/CSV/Markdown/HTML, remediation-plan export (CSV, spreadsheet CSV), SARIF 2.1.0, image inventory with evidence gaps, component inventory and `components where` from stored SBOMs , retired images apart, inventory changes per period, aggregated CycloneDX 1.6 inventory BOM; open findings per owning team and an owner (point of contact) per remediation-plan item (ADR 0024); exports to OWASP Dependency-Track (SBOMs per target) and DefectDojo (Generic Findings reimport mirroring closure; ADR 0027) |
| F9 | Notifications: pluggable (SMTP, webhook, Matrix, Mattermost, Slack, GitLab/GitHub issues), deduplicated, digest mode. | ✅ `Notifier` extension point, events after each monitor cycle (new critical/KEV, SLA due soon/breached, health opened, fixed), sent once per channel, digest mode, `notify_failed` health finding (ADR 0015); webhook (Standard Webhooks signatures), SMTP (TLS required), Slack, Mattermost, Matrix; GitHub and GitLab issues per target and vulnerability, closed on scan evidence; team channels receive only their teams' images (ownership by reference patterns, ADR 0024) |
| F10 | Self-health as findings: scanner failures, stale DBs, missed schedules, auth failures, checksum mismatches. | ✅ |
| F11 | Helm: ingest charts (HTTP, OCI, Artifact Hub), render, extract every image, flag operator-managed images, track neglected charts, upstream-contribution queue (human-approved). | ⬜ (OCI Helm charts are already *rejected* safely as non-images) |
| F12 | Registries: AWS ECR (cross-account, multi-region, all AWS partitions, ECR Public), GitLab.com + self-managed, generic OCI. Short-lived credentials only. No Docker daemon. | ✅ any OCI registry, no daemon; native ECR (any AWS partition, cross-account via roles) and GCR/Artifact Registry credentials; docker config/credential helpers for the rest ; `RegistryProvider` extension point with bounded repository and tag listing (ADR 0013) ; ECR through its API with role assumption for other accounts and listing with push times; GitLab.com and self-managed (job and deploy tokens, group and project listing) |

## Security requirements (non-negotiable)

| ID | Requirement | Status |
|---|---|---|
| S1 | Never execute image content. Bound sizes, time and output; protect against path traversal / symlink escape. | ✅ manifest/layer/total limits, digest verification, scanner timeouts, output limits, SBOM size/shape validation, scanner sandbox by default with seccomp and W^X — `bwrap` (Linux hosts) or `landlock` (containers) — offline scanning with a separate DB update step, scratch quota and free-disk floor; hostile fixture suite in CI with real scanners |
| S2 | Credentials never logged, never persisted, redacted from errors. Least-privilege IAM policy shipped and tested. | ✅ redaction, scanners never receive registry credentials, env allowlist; least-privilege IAM policy and pinned trust policies in `deploy/iam`, tested |
| S3 | Own supply chain: scanners pinned by checksum, CI actions pinned by full SHA, reproducible signed releases. | 🟡 binary SHA-256 pins, pinned CI actions, checksum-verified installer; scanner release signatures verified with cosign against pinned workflow identities (ADR 0006); release pipeline: reproducible binaries (goreleaser), CycloneDX SBOM per archive, keyless-signed checksums, SLSA provenance, signed image on GHCR (docs/processes/release.md; first tagged release pending) · ⬜ SBOM attestation of the image |

> The original requirements prompt was truncated after "S3 Own su…"; S3 above is
> reconstructed from the surrounding notes (scanner pinning after CVE-2026-33634).
> Confirm or amend it.

## Finding lifecycle

```
                 ┌──────────── manual ────────────┐
   (detected) → open ⇄ triaged ⇄ in_remediation   │
                 │        │          │            │
                 └────────┴──────────┴─ decision ─┴→ risk_accepted (expires → reopened)
                                                    not_affected
   engine only, with scan evidence:
     absent from successor digest (complete scan)  → fixed
     still present in successor digest             → superseded (successor inherits state)
     vanished from the same digest (DB changed)    → withdrawn
     re-detected / regression / decision expired   → reopened
```

`superseded` and `withdrawn` extend the original state list; see
[ADR 0004](docs/adr/0004-finding-lifecycle.md) for why they are needed for honest MTTR.

## Non-goals (for now)

- Runtime/in-cluster scanning (Trivy Operator covers it; we may ingest its output).
- A web UI before the data model and CLI are stable (M6).
- Proprietary scanners or feeds.
