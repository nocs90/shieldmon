# Monitored image inventory

Generated: 2026-10-28T12:00:00Z · Monitored targets: 5 · Distinct digests: 3 · With evidence gaps: 3 · Retired: 1

## Evidence gaps

| Gap | Images |
|---|---:|
| last_scan_partial | 1 |
| missing_sbom:trivy | 1 |
| stale_evidence | 1 |
| unresolved | 1 |

## Images

| Image | Digest | Last complete scan | Scanners | SBOMs | Open (C/H/M/L) | Gaps |
|---|---|---|---|---|---|---|
| =registry.test/evil\|x:1 (linux/amd64) | `sha256:cccccccccccc…` | 2026-10-23T12:00:00Z | grype 0.86.1 (DB 2026-10-28); trivy 0.67.2 (DB 2026-10-27) | syft | 0/0/0/0 | stale_evidence, missing_sbom:trivy |
| registry.test/app:latest (linux/amd64) | `sha256:aaaaaaaaaaaa…` | 2026-10-28T11:00:00Z | grype 0.86.1 (DB 2026-10-28); trivy 0.67.2 (DB 2026-10-27) | syft, trivy | 1/1/0/0 |  |
| registry.test/app:prod (linux/amd64) | `sha256:aaaaaaaaaaaa…` | 2026-10-28T11:00:00Z | grype 0.86.1 (DB 2026-10-28); trivy 0.67.2 (DB 2026-10-27) | syft, trivy | 1/1/0/0 |  |
| registry.test/app:prod (linux/arm64) | `sha256:bbbbbbbbbbbb…` | 2026-10-27T12:00:00Z | grype 0.86.1 (DB 2026-10-28); trivy 0.67.2 (DB 2026-10-27) | syft, trivy | 0/0/0/1 | last_scan_partial |
| registry.test/legacy:1 (linux/amd64) | `sha256:dddd` |  |  |  | 0/0/0/0 | retired 2026-10-08 |
| registry.test/never:1 (linux/amd64) | — |  |  |  | 0/0/0/0 | unresolved |

## Base images

Images with a known base: 3 · On the newest base: 0 · Rebuild available: 2 · Base not verified: 1 · Unmaintained base: 2

| Image | Base | Source | Status | Newest base since | Unmaintained |
|---|---|---|---|---|---|
| registry.test/app:latest (linux/amd64) | registry.test/base:1 | annotation | rebuild available | 2026-07-20 | yes |
| registry.test/app:prod (linux/amd64) | registry.test/base:1 | configured | rebuild available | 2026-07-20 | yes |
| registry.test/app:prod (linux/arm64) | registry.test/other:2 | annotation | unknown |  |  |
