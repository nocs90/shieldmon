# 0028 — OSV-Scanner as an optional, offline third matcher

- Status: proposed (accepted once the parity numbers below are recorded from CI)
- Date: 2026-11-01

## Context

- A third free matcher improves language-ecosystem coverage (#39). OSV-Scanner v2.7.0
  (2026-10-12) reads CycloneDX SBOMs and matches them against the OSV.dev data, which merges
  GitHub advisories, PyPA, Go, RustSec and distro feeds.
- By default it queries `api.osv.dev` with the package list. ADR 0011 forbids network to any
  process that reads an SBOM, and an inventory of a private image is itself sensitive.
- Its offline mode (`--offline`, which also disables transitive resolution and every other
  network plugin) reads per-ecosystem databases from
  `$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY/osv-scalibr/<ecosystem>/all.zip`. Read from the
  v2.7.0 source (`osv-scalibr` `enricher/vulnmatch/osvlocal`): a database is downloaded only
  for the ecosystems of the packages being scanned, only with `--download-offline-databases`,
  and only when its CRC32C differs from the remote copy.
- When a database is missing it logs an error and goes on; with vulnerabilities found in other
  ecosystems it still exits 1 (`cmd/osv-scanner/internal/cmd/run.go`: the "vulnerabilities
  found" status takes precedence over logged errors). The result is silently incomplete, which
  ADR 0004 cannot accept: absence-based closure needs complete scans.
- It exits 1 when it finds vulnerabilities, 127 on errors, 128 when there are no packages.
- It picks its SBOM parser by file name (`*.cdx.json`, `bom.json`) and reads `-L` up to the
  first `:` as a parser name; ShieldMon stores SBOMs as `<generator>.cyclonedx-json.json`.
- From a CycloneDX SBOM it maps PURLs to ecosystems for language types and for `apk` and `deb`
  (Alpine, Wolfi, Chainguard, Debian, Ubuntu); `rpm` packages get no ecosystem and are skipped
  (`purl/ecosystem/ecosystem.go`, `extractor/convert.go`). grype and trivy remain the matchers
  for RHEL/UBI OS packages.
- Releases ship raw binaries (57 MB linux/amd64), a `SHA256SUMS` file that is not signed, and
  SLSA v0.2 provenance (`multiple.intoto.jsonl`, a Sigstore bundle) signed by
  `slsa-github-generator`'s `generator_generic_slsa3.yml@refs/tags/v2.1.0` with
  `google/osv-scanner` and `refs/tags/v2.7.0` in the certificate. `cosign 3.1.3
  verify-blob-attestation` verifies it and refuses a changed binary, another tag and another
  repository (checked 2026-11-01).

## Decision

- Adapter `osv-scanner` (`internal/scanner/osv.go`), a matcher on syft SBOMs, optional (not in
  the default `matchers`). Options: `db_auto_update` (default true) and `ecosystems` (default
  every ecosystem in `scanner.OSVEcosystems`; unknown or repeated names are refused).
- ShieldMon, not osv-scanner, decides what is matched: it maps each SBOM component's package
  URL to an OSV ecosystem (`apk` of Alpine, Wolfi, Chainguard; `deb` of Debian, Ubuntu; npm,
  PyPI, Go, Maven, crates.io, RubyGems, NuGet, Packagist, Hex, Pub) and hands osv-scanner a
  private copy (`sbom.cdx.json`) with those components only. Other types (rpm, Bitnami,
  generic, …) are left to grype and trivy. A component of a supported ecosystem missing from
  `ecosystems` fails the match, naming it; so does a configured ecosystem without a database,
  checked before scanning. With no matchable component the result is empty and nothing runs.
- `Match` runs `osv-scanner scan source --offline --verbosity error --format json -L <copy>`.
  Exit status 1 is accepted (`Runner.OKExitCodes`), and any output on stderr, which then holds
  errors only, fails the match whatever the status (`Runner.RunWithStderr`). A package in an
  ecosystem ShieldMon did not hand over fails it too.
- `UpdateDB` makes osv-scanner download the configured ecosystems by scanning a probe SBOM that
  ShieldMon writes: one placeholder package per ecosystem, named `shieldmon db-probe` (a space:
  no registry can publish it, so no advisory can match it), never an image's SBOM. Any non-zero
  status, any logged error, any match on a probe or a configured database still missing fails
  the update. Only then is each database marked verified now (its mtime), the time its content
  was known to equal the remote copy. `DBBuilt` is the oldest database a match used, so
  `db_stale` covers each ecosystem.
- One raw match per osv-scanner group, every ID and alias (including `upstream`) as aliases, so
  that normalization maps it to its CVE; severity from the group's `max_severity` CVSS score,
  else the database's label; fixed versions from the affected entry of the package's ecosystem
  release.
- `scripts/install-scanners.sh` pins it by SHA-256 and verifies its SLSA provenance with cosign;
  it installs it only when asked (`SCANNERS="syft grype trivy osv-scanner"`). The container
  image does not ship it. (Prepared as `.git/task-patches/39-osv-installer-and-ci.patch` with the
  CI integration job change and the ADR 0006, quality-gates and threat-model updates: those
  files need a maintainer's review before they change.)

## Parity

`TestOSVParity` (integration) matches the same syft SBOMs with grype and osv-scanner and logs
the findings found by both, by grype only and by osv-scanner only, per package type. To record
from the first CI run with osv-scanner installed:

| Image | Type | Both | grype only | osv-scanner only |
|---|---|---:|---:|---:|
| alpine:3.18.0 | apk | — | — | — |
| python:3.12.7-alpine3.20 | apk | — | — | — |
| python:3.12.7-alpine3.20 | pypi | — | — | — |

## Consequences

- No package list leaves the host while matching; the only network is the database download,
  which sees ShieldMon's probe SBOM only.
- A missing or unreadable ecosystem database fails the match (health finding, scan partial)
  instead of hiding findings: absence-based closure never rests on an incomplete osv-scanner
  result. Adding an ecosystem to `ecosystems` fixes the missing case at the next update.
- Removing an ecosystem from `ecosystems`, like removing a matcher, ends osv-scanner's evidence
  for it: its osv-only findings are no longer reported.
- Large ecosystems (Debian, Ubuntu, npm, Maven) are hundreds of MB each and change daily;
  `ecosystems` should list the ones the monitored images use.
- The adapter depends on osv-scanner's database layout and exit codes: a version bump re-checks
  them (unit tests use a fake binary; `TestOSVParity` and `scannertest.CheckMatcher` run the real one).
