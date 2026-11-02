# Changelog

All notable changes are listed here; release notes on GitHub add the full list of merged
pull requests. Versioning follows [SemVer](https://semver.org): before 1.0, a minor release
may change configuration and JSON output (called out under "Breaking changes").

## [Unreleased]

### Server mode

- `shieldmon serve`: a built-in scheduler (the monitoring cycle, charts first, every
  `health.monitor_interval`, retried a minute later when a command holds the data directory)
  and an HTTPS API to read findings, targets, health and reports and to triage and decide.
  Roles (viewer, triager, admin) and API tokens, stored as SHA-256 hashes; decisions are
  authored `api:<token name>`, a prefix no other author can take (command line, VEX). TLS
  required beyond loopback; bounded requests and lists (ADR 0031,
  docs/processes/server.md).

### Matchers

- OSV-Scanner as an optional third matcher, offline: databases per ecosystem refreshed by the
  separate update step, results refused unless complete (every package it was given comes
  back, no vulnerability outside a group, no unlisted ecosystem), so absence never closes a
  finding on a partial result. `scripts/install-scanners.sh` installs it on request with its
  SLSA provenance verified (ADR 0028).

### Release

- A release is cut from `main` only; release candidates may be tagged on a release branch.
  CI builds the release configuration on every pull request (`release-dry-run`).

## [0.3.0] — 2026-11-02

The first public release. ShieldMon monitors container images continuously: it resolves tags
to digests, generates SBOMs once per digest, re-matches them against fresh vulnerability data
every cycle, and closes a finding only when a later scan proves it gone.

### Monitoring core

- Digest identity: findings are keyed by (image digest, canonical PURL, canonical
  vulnerability ID); multi-platform indexes resolve to the configured platform.
- SBOM-first pipeline: syft (CycloneDX + SPDX) and trivy (CycloneDX) generate once per digest;
  grype and trivy match the stored SBOMs every cycle without pulling the image again.
- Normalization and de-duplication across scanners and aliases (CVE, GHSA, distro IDs).
- Evidence-based lifecycle: fixed, superseded and withdrawn only from complete scans;
  carry-over to successor digests; regressions reopen; decisions (risk acceptance with
  expiry, not affected) under a configurable remediation policy with documented deviations.
- Append-only, hash-chained audit trail, verified on schedule and anchored by exported
  digests and by every report.
- Self-health as findings: scanner failures, stale DBs, missed cycles, registry
  authentication failures, checksum mismatches, unsandboxed scanners.
- Concurrent monitoring with a bounded worker pool and per-registry rate limits.

### Inputs and registries

- Targets from references, list files, registry repositories and paths (tag filters,
  latest-N), and rendered Kubernetes manifests: `helm template`, kustomize, `kubectl get`
  (`targets add --manifests`; custom resources are flagged as operator-managed).
- Registry providers: AWS ECR (IAM roles, IRSA, Pod Identity, cross-account, every
  partition, ECR Public), Google GCR/Artifact Registry, GitLab.com and self-managed (job,
  deploy and API tokens), and any OCI registry through docker credentials. A
  least-privilege IAM policy ships in `deploy/iam`.
- Target retirement that keeps the history.

### Helm charts

- Chart sources: HTTP chart repositories, OCI registries and Artifact Hub, with versions,
  bounded downloads, digest checks and archive checks (links, escaping paths, appended or
  nested archives, size bombs) before anything renders them; content from remote sources
  only reaches public addresses (`charts list | versions | fetch`).
- Rendering per values profile with a pinned helm, its release signature verified, run in
  the scanners' sandbox: no network, nothing of the host but the checked archive and the
  profile's values (`charts images`, `targets add --chart`).
- Release tracking: `monitor` follows each chart's newest release, records what every
  version runs per profile (append-only, audited) and can add its images as targets,
  bounded against a hostile publisher (public or configured registries only, a cap on new
  targets and renders).
- Neglected charts from scan evidence: a release that keeps vulnerabilities with fixes past
  the policy, or a chart that stopped releasing (`charts status | history`); upstream issue
  drafts for the maintainers, never submitted by ShieldMon (`charts draft-issue`).

### Prioritization and remediation

- CISA KEV enrichment and a priority score with reasons (CVSS, KEV/EPSS, fix availability,
  SLA clock), plus runtime context from read-only cluster exports: running images rank
  higher, exposed ones higher still.
- Base image lineage: configured or annotated bases proven by shared layers; rebuild
  available, unmaintained, configured successors; per finding, whether a rebuild fixes it.
- Policy gate for CI (`shieldmon gate`): exit codes, SARIF, exemptions only by decisions or
  VEX, fails closed on incomplete evidence.

### VEX, reports, notifications, exports

- OpenVEX and CycloneDX VEX import as scoped `not_affected` statements; OpenVEX export.
- Monthly lifecycle report (opened, fixed, MTTR, burndown, SLA breaches, accepted-risk aging)
  as Markdown, HTML, JSON, CSV and SARIF; remediation plan (CSV, spreadsheet); image and
  component inventory, inventory changes, CycloneDX inventory BOM.
- Notifications: webhook (Standard Webhooks signatures), SMTP, Slack, Mattermost, Matrix,
  GitHub and GitLab issues (closed on scan evidence); deduplicated, digest mode, per-owner
  routing.
- Exports to OWASP Dependency-Track and DefectDojo.
- Ownership: teams by reference patterns, per-team reports and channels.

### Security of ShieldMon itself

- Scanners run in a sandbox by default (bubblewrap on hosts, Landlock in containers), with
  seccomp, W^X, no network while reading image content, a read-only DB cache, scratch quotas
  and a free-disk floor; a hostile-fixture suite runs in CI with real scanners.
- Scanners never receive registry credentials; secrets are redacted from logs, errors,
  health findings and reports; hostile strings are escaped in every output format.
- Scanner binaries are pinned by SHA-256 and their release signatures verified with a pinned
  cosign against the exact release workflows; helm by SHA-256 and its OpenPGP signature
  against the pinned release key.
- Reproducible release binaries with SBOMs, keyless-signed checksums and SLSA provenance; a
  distroless, non-root container image, signed and gated by ShieldMon itself in CI.

### Known limitations

- macOS has no scanner sandbox (`--sandbox none`, reported as a health finding); there helm
  renders charts unconfined too, with a warning.
- SQLite only: one ShieldMon process per data dir.
- Private HTTP chart repositories (basic auth) are not supported yet; private OCI charts use
  the registries' credentials.
- The container image bundles syft and grype releases built with Go 1.26.8; two Go stdlib
  advisories that do not apply to them are recorded as reviewed VEX statements
  (`security/vex/`), until upstream releases a build with a newer Go.

### Not yet in this release

Server mode (`shieldmon serve`, in review), the OSV-Scanner matcher (in review), PostgreSQL,
OIDC, submitting upstream contributions through an API, Copacetic patch proposals, native
report signing. See [ROADMAP.md](ROADMAP.md); contributions are welcome
([CONTRIBUTING.md](CONTRIBUTING.md)).
