# The monitoring cycle

`shieldmon monitor` runs one cycle; a scheduler (cron, systemd timer, Kubernetes CronJob)
runs it every `health.monitor_interval` (default 24h). `shieldmon scan REF` runs the same
per-target steps for one reference and registers it as a target.

Targets can also be registered without scanning, for the next cycle to pick up:
`shieldmon targets add REF… | -f FILE` and `shieldmon targets add-repo REPO [--under]
[--tag-regex RE] [--latest N]`, which lists tags (newest first) and repositories through the
registry's provider (registries.md). Both take `--dry-run`.

## Steps

| # | Step | Code | Evidence recorded | On failure |
|---|---|---|---|---|
| 0 | Take the data-dir lock (one cycle at a time) | `engine.Lock` | — | command exits; nothing changes |
| 1 | Schedule check: was the previous cycle on time? | `Engine.Monitor` | `monitor_runs` | `monitor_missed` health finding |
| 2 | Expire decisions past their date → `reopened` | `store.ExpireDecisions` | `finding_events` | — |
| 2a | Preflight (only when there are targets): record whether scanners are sandboxed; refresh each matcher's vulnerability DB — the only scanner processes with network, and they never see image content or SBOMs | `Engine.Preflight` | — | `scanner_unsandboxed`; `db_update_failed` (the cycle goes on with the DBs on disk) |
| 3 | For each target: resolve tag → index → platform manifest digest | `oci.Resolve` | `targets.current_digest`, `target_digests` (on change) | `registry_auth` / `resolve_failed`; target skipped |
| 4 | If an SBOM is missing for a required generator: fetch once (limits checked first, digests verified) into a private temp OCI layout | `oci.Fetch` | — | `fetch_failed` / `registry_auth`; scan fails |
| 5 | Generate SBOMs (syft: CycloneDX + SPDX; trivy: CycloneDX) without network, validate, store with SHA-256; delete the layout | `engine.generate` | `sboms` | `sbom_generator_failed` / `scanner_checksum_mismatch` |
| 6 | Run each matcher on its own generator's SBOM without network and with the DB read-only; record tool + DB version + DB build time | `scanner.*.Match` | `scans.tools` | `matcher_failed`; scan becomes **partial** |
| 7 | DB freshness check per matcher | `engine.checkDBAge` | — | `db_stale` |
| 8 | Normalize and deduplicate | `normalize.Merge` | — | — |
| 9 | Reconcile lifecycle (pure plan, applied in one transaction) | `lifecycle.Reconcile`, `store.ReconcileScan` | `findings`, `scan_matches`, `finding_events`, `decisions` (carried) | transaction rolled back; scan marked failed |
| 9a | Notify: compute events from the store, record them, send each channel what it has not been sent (notifications.md) | `Engine.Notify` | `notification_events`, `notifications` | `notify_failed` per channel; the run becomes **degraded**; events wait for the next cycle |
| 10 | Close the run with status ok / degraded / failed | `store.FinishMonitorRun` | `monitor_runs` | — |

`scan` and `rematch` run the preflight too; `shieldmon db update` runs only the DB refresh
and exits non-zero when it fails.

Unchanged digest ⇒ steps 4–5 are skipped: the cycle is one manifest request plus the
matcher runs (SBOM-first).

## Exit codes

`monitor` exits non-zero when the run is `degraded` or `failed`, so the scheduler's own
alerting fires as well as ShieldMon's health findings.

## Running it by hand

```sh
shieldmon monitor --log-level info
shieldmon health            # anything open needs attention, see health-findings.md
```
