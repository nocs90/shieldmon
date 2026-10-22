# 0006 — Scanners never see credentials or registries

- Status: accepted
- Date: 2026-10-20

## Context

Scanners parse hostile layers and have been compromised upstream (trivy release and
GitHub Action tags, March 2026, CVE-2026-33634). A ConMon tool runs them next to ECR and
GitLab credentials.

## Decision

- ShieldMon resolves and fetches images itself (credentials stay in the ShieldMon process)
  and hands generators a local OCI layout; matchers get a stored SBOM path.
- Scanner processes get an **allowlisted environment** (PATH, HOME, proxies, CA bundles,
  `SYFT_*`/`GRYPE_*`/`TRIVY_*`); no `AWS_*`, `DOCKER_CONFIG`, tokens.
- No shell: argv only; refs validated; digest-pinned.
- Bounded: timeout, own process group killed on timeout, stdout byte limit that kills
  the process on overflow, stderr truncated and redacted.
- Telemetry and update checks disabled (`--disable-telemetry`, `--skip-version-check`,
  `*_CHECK_FOR_APP_UPDATE=false`).
- Optional SHA-256 pin per scanner binary in config; mismatch aborts and opens a
  `scanner_checksum_mismatch` health finding. `shieldmon doctor` prints current hashes.
- CI installs scanners via `scripts/install-scanners.sh` with in-repo checksums; Actions
  are pinned by full commit SHA.

## Consequences

- Credential exposure is limited to one well-reviewed code path (`internal/oci`).
- Remaining gap: scanners still run with the user's filesystem access; sandboxing is M2.
