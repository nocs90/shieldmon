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

## Amendment (2026-10-31): release signatures (#9)

A checksum recorded in this repository proves that an archive did not change since it was
pinned, not that the project released it: the checksums file comes from the same release as
the archive. Each project signs that file in GitHub Actions with Sigstore keyless signing
(syft and trivy: a Sigstore bundle; grype: a signature and a certificate), an anchor
independent of this repository.

- `scripts/install-scanners.sh` verifies each release's signed checksums file with cosign
  against the **exact** certificate identity of the release workflow and the GitHub Actions
  OIDC issuer, read from the certificates of the pinned releases:

  | Scanner | Identity |
  |---|---|
  | syft | `https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main` |
  | grype | `https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main` |
  | trivy | `https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v<version>` |

- The archive must then be listed in the signed file **with** the SHA-256 pinned here, and
  match it. A wrong signer, a changed file or a missing entry aborts the installation; nothing
  is installed until every scanner verified.
- cosign is itself pinned by version (3.1.3, older than the 14-day minimum age) and SHA-256
  per host; `COSIGN=/path` uses a binary already there only if it is that one.
- Sigstore's TUF repository and Rekor are reached online (a transient failure is retried
  three times). A pinned `trusted_root.json` would allow offline checks of the bundles, but
  Sigstore rotates those keys and grype's signature needs Rekor anyway.
- Bumping a scanner checks the identity still matches; projects changing their release
  workflow change it on purpose, and the script fails until this table is updated.

Checked on 2026-10-31: the three pinned releases verify; a wrong identity and a changed
checksums file are refused. grype's `--certificate` form is deprecated in cosign 3 in favour of
bundles; when grype publishes bundles, switch to them.

## Consequences

- Credential exposure is limited to one well-reviewed code path (`internal/oci`).
- Remaining gap: scanners still run with the user's filesystem access; sandboxing is M2.
- Installing scanners needs Sigstore's public endpoints (TUF, Rekor) besides GitHub.
