# Responding to health findings

A health finding means the monitoring evidence has a gap. Failures of detection are
themselves vulnerabilities: treat them with the same urgency.

| Check | Meaning | Typical fix | Auto-resolves when |
|---|---|---|---|
| `registry_auth` | 401/403 from a registry | renew credentials / credential helper, check role trust | next successful resolve/fetch for that registry |
| `resolve_failed` | tag cannot be resolved (404, network) | tag deleted? network/proxy | next successful resolve of that ref |
| `fetch_failed` | image download failed or exceeded `limits` | raise limits deliberately, check registry | next successful fetch |
| `sbom_generator_failed` | syft/trivy could not catalog the image | check `shieldmon doctor`, scanner version | next successful generation |
| `matcher_failed` | grype/trivy matching failed (often DB download) | network to DB mirrors, disk space | next successful match |
| `scanner_checksum_mismatch` | binary differs from the pinned SHA-256 | **treat as a possible compromise**: verify the binary's origin before re-pinning | next run with a matching binary |
| `db_stale` | vulnerability DB older than `health.db_max_age` | fix DB updates (network, `skip_db_update`) | next match with a fresh DB |
| `monitor_missed` | gap between cycles > 1.5 × `monitor_interval` | fix the scheduler | next on-time cycle |

`shieldmon health --all` shows resolved ones with occurrence counts.
