# 0026 — Concurrent monitoring: a bounded pool, one scan per digest at a time

- Status: accepted
- Date: 2026-10-31

## Context

- `monitor` scans targets one after the other. A cycle over hundreds of images is bound by
  scanner processes and downloads, not by the database: a fleet takes hours (#13).
- Each scan process holds a vulnerability DB in memory (grype and trivy, a few GB each while
  matching) and up to `limits.max_total_bytes` + `limits.max_scratch_bytes` of disk: running
  N at once needs N times that.
- Two targets can resolve to the same digest (`app:prod` and `app:1.4`). Generating its SBOMs
  twice at the same time would race on `sboms` UNIQUE (digest, generator, format) and fetch
  the image twice; reconciliation already runs in one transaction on the single SQLite
  connection.
- Registries throttle and ban clients that burst: Docker Hub's anonymous limits, private
  registries behind small instances.

## Decision

- `monitor` scans up to `scanners.concurrency` targets at once (`--concurrency N` overrides;
  default 1, the previous behaviour). DB updates run once before the pool, notifications and
  audit verification once after it.
- SBOM generation and matching of a digest are serialized by a lock per digest, held only
  around them: no other lock is taken while it is held, so locks cannot deadlock. Each base
  reference is still observed once per cycle (ADR 0022).
- Requests of the monitoring cycle (resolve, fetch, inspect) are rate-limited per registry
  host: `limits.registry_rps` requests per second with bursts of as many (default 10; 0
  disables). Repository listing (`targets add-repo`) is bounded by its own limits instead.
- The store keeps its single connection: writes queue; nothing else changes in the
  lifecycle or the audit trail.

## Consequences

- Memory and scratch space must be sized for `concurrency` scans: the deployment examples
  stay at 1 and say how to raise it.
- Results keep the order of the targets; logs interleave (`--log-format json` carries the
  target in each line).
- Proven by a race-detector test of a cycle with shared digests: one SBOM generation per
  digest, the same findings as a sequential cycle.
