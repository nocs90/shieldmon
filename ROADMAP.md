# Roadmap

The backlog behind this roadmap (epics and tasks, with acceptance criteria) is in
`.github/backlog/backlog.json` and published as GitHub issues, milestones and the
**ShieldMon Roadmap** Project by `scripts/github/bootstrap.py`
(see [docs/processes/issue-management.md](docs/processes/issue-management.md)).

**v0.3.0** (the first public release) contains M1–M5, M3's inputs and providers, and from
M7 the base-image lineage, runtime context, images of rendered manifests and Helm charts
(sources, sandboxed rendering, release tracking, neglected charts, upstream drafts)
([CHANGELOG.md](CHANGELOG.md)). Server mode (M6) and the OSV-Scanner matcher are next.

Each milestone ends with an executable definition of done. A milestone is closed when its
checks pass in CI and an independent review of the diff (fresh context) finds no blocker.

## M1 — Core ConMon loop ✅

Digest identity, SBOM-first pipeline, syft/grype/trivy adapters, normalization and
dedupe, SQLite with append-only audit, evidence-based lifecycle, decisions with expiry,
self-health findings, monthly report (md/json/csv), CLI.

Also in M1: plugin registry for scanners and report formats with a conformance kit
(ADR 0008), quality gates (ADR 0009), fuzzing of hostile-input parsers, process docs.

**Done when:** `make lint test-race cover fuzz build` green; `make test-integration` green (real
scanners on a pinned digest, second scan is a rematch without a pull); the scenario test
`TestContinuousMonitoringLifecycle` covers fix-by-successor, carry-over, partial-scan
safety, regression, stale DB, auth failure and report numbers.

## M2 — Hardening & packaging

- Run scanners in a sandbox ([ADR 0011](docs/adr/0011-scanner-sandbox.md)): bubblewrap on
  Linux hosts, Landlock in containers, seccomp, private scratch space; no network while touching
  image content, vulnerability DBs refreshed by a separate `db update` step.
- Container image for ShieldMon (distroless, non-root, scanners installed by
  `scripts/install-scanners.sh`), multi-arch pins.
- Scanner signature verification (cosign) in addition to checksums.
- Release pipeline: reproducible builds, SBOM + provenance for ShieldMon itself, signed.
- Deployment examples: systemd timer, Kubernetes CronJob with PVC.
- Structured JSON logging; `--log-format json`.
- Parallel scanning with a bounded worker pool.
- Dogfooding: ShieldMon scans its own image in CI. Coverage floor 50% → 70%.
- Repository settings: branch protection with required gates, Discussions.

**Done when:** a hostile-fixture suite (zip-bomb layer, 10k-layer manifest, symlink
escape, giant SBOM, scanner that never exits) runs in CI with every case bounded and
reported as a health finding; image runs as non-root with read-only root FS.

## M3 — Registries & inputs (F1, F12)

- Native AWS ECR provider: IAM role / IRSA / EKS Pod Identity / OIDC web identity,
  cross-account, multi-region, all AWS partitions, ECR Public; repository listing.
- GitLab provider: CI job token, OIDC `id_tokens`, deploy tokens (`read_registry`);
  project/group registry listing; self-managed instances.
- Inputs: image list files, whole repositories (tag filters), "latest N tags".
- Shipped least-privilege IAM policy + test that asserts the exact action set.

**Done when:** integration tests against ECR (sandbox account via CI OIDC) and a
GitLab project pass; no long-lived credentials anywhere in config or CI.

## M4 — Prioritization, VEX, notifications (F5, F6, F9)

- OpenVEX and CycloneDX VEX import/export; decisions scoped by product/digest/PURL.
- Priority score: CVSS + EPSS + CISA KEV catalog (fetched, cached, health-checked) +
  fix availability; SLA clocks per profile; `findings list --sort priority`.
- Notifications: SMTP, webhook, Matrix, Mattermost, Slack, GitLab/GitHub issues;
  deduplicated, digest mode, health findings included.
- Ownership: targets assigned to teams; reports and notifications routed per owner
  (as in Kondukto / DefectDojo).
- Policy-as-code CI gate `shieldmon gate` with configurable exit codes and SARIF (as in
  Anchore Enterprise).
- OSV-Scanner matcher adapter, offline (ADR 0028).

## M5 — Compliance profiles (F8)

- Fully configurable remediation policy profiles (deadlines per severity, decision
  limits), documented so that an organization can map its own policy onto them.
- Remediation-plan export (one row per open item with milestones and deviations),
  inventory export for audits.
- HTML report, SARIF export, accepted-risk aging.
- Hash-chained audit log; signed report exports.

## M6 — Server mode (F4)

- PostgreSQL backend sharing the schema; migration tests on both engines.
- `shieldmon serve`: scheduler, API, OIDC auth, RBAC (decisions need a role), web UI.
  Done (ADR 0031): scheduler, read and decision API, roles, API tokens; next: OIDC, web UI.
- Export to OWASP Dependency-Track (portfolio, trends) and DefectDojo instead of
  rebuilding them (ADR 0001).

## M7 — Remediation & Helm (F7, F11)

- Base-image upgrade candidates (same lineage, newer tag) with finding diff (as in Snyk).
- Runtime context for prioritization: is the image running, is it exposed (as in
  Wiz / Prisma), from a read-only cluster inventory (ADR 0029).
- Copacetic patch proposals for OS packages.
- Helm: ingest charts (HTTP repo, OCI, Artifact Hub), render with values profiles,
  extract every image (containers, initContainers, ephemeral, hook Jobs), flag
  operator-managed images, track per chart version, detect neglected charts ✅ (ADR
  0030, 0032–0034).
- Upstream-contribution queue: issue drafts with evidence ✅ (`charts draft-issue`, never
  submitted); submission through an API, deduplicated against existing issues,
  rate-limited, after a recorded approval ⬜ (#37).

## Open questions for the maintainer

1. S3 text was truncated in the source notes — confirm the intended requirement.
2. Default SLA days for the commercial profile (currently 15/30/90/180).
3. Is a web UI in scope before server mode, or is CLI + reports enough for early adopters?
