# Responding to health findings

A health finding means the monitoring evidence has a gap. Failures of detection are
themselves vulnerabilities: treat them with the same urgency.

| Check | Meaning | Typical fix | Auto-resolves when |
|---|---|---|---|
| `registry_auth` | 401/403 from a registry | renew credentials / credential helper, check role trust | next successful resolve/fetch for that registry |
| `resolve_failed` | tag cannot be resolved (404, network) | tag deleted? network/proxy | next successful resolve of that ref |
| `fetch_failed` | image download failed or exceeded `limits` | raise limits deliberately, check registry | next successful fetch |
| `sbom_generator_failed` | syft/trivy could not catalog the image, or was killed for exceeding `limits.max_scratch_bytes` / `limits.min_free_disk_bytes` (the detail says which) | check `shieldmon doctor`, scanner version; a quota breach on an unknown image may be a decompression bomb — raise the limit only after looking at the image | next successful generation |
| `matcher_failed` | grype/trivy matching failed | check `shieldmon doctor`, disk space; a missing DB means `db update` never succeeded | next successful match |
| `db_update_failed` | `db update` could not refresh a matcher's DB (the cycle goes on with the DB on disk) | network to DB mirrors, disk space; `db_stale` follows if it keeps failing | next successful update |
| `scanner_checksum_mismatch` | binary differs from the pinned SHA-256 | **treat as a possible compromise**: verify the binary's origin before re-pinning | next run with a matching binary |
| `db_stale` | vulnerability DB older than `health.db_max_age` | fix DB updates (network, `db_auto_update`/`skip_db_update`, or the out-of-band process that manages the DB) | next match with a fresh DB |
| `scanner_sandbox_degraded` | the sandbox runs without one of its guarantees on this host; today: `bwrap` on a kernel without Landlock ABI ≥ 2, where a scanner can execute files it writes | a kernel with Landlock (Linux ≥ 5.19, `landlock` in the LSM list), or `backend: landlock`; until then a `noexec` scratch filesystem (`deploy/scratch`) keeps scanner output non-executable | next cycle with full guarantees |
| `scanner_unsandboxed` | `scanners.sandbox.backend: none`: scanners parse hostile layers with the invoking user's files and network ([ADR 0011](../adr/0011-scanner-sandbox.md)) | choose a backend that runs here (`shieldmon plugins`) | next cycle with a confining backend |
| `monitor_missed` | gap between cycles > 1.5 × `monitor_interval` | fix the scheduler | next on-time cycle |

`shieldmon health --all` shows resolved ones with occurrence counts.
