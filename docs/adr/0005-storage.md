# 0005 — SQLite now, PostgreSQL later, one portable schema

- Status: accepted
- Date: 2026-10-20

## Context

CLI/single-node users need zero-ops storage; server mode needs concurrency and HA.

## Decision

- SQLite (WAL, foreign keys, immediate transactions, single connection) for M1.
- Schema in versioned, embedded SQL migrations (`internal/store/migrations`), written in
  the SQL subset shared with PostgreSQL (TEXT timestamps in RFC 3339 UTC, INTEGER ids,
  JSON in TEXT). PostgreSQL gets its own migration directory when added (M6), with tests
  running the same store suite on both engines.
- Audit tables (`finding_events`, `scan_matches`, `target_digests`, `decisions`) are
  append-only, enforced by triggers (rules/grants in PostgreSQL).
- SBOM blobs live on disk under `data_dir/sboms/` with their SHA-256 in the DB
  (object storage in server mode).
- An exclusive lock on the data directory prevents concurrent cycles.

## Consequences

- Backups are a file copy (with `sqlite3 .backup` for consistency).
- Reports replay events in memory; fine for tens of thousands of findings, revisit with
  materialized daily snapshots if it becomes slow.

## Update 2026-10-21: what comparable tools use

| Tool | Database |
|---|---|
| OWASP Dependency-Track v5 | PostgreSQL only (H2, MySQL, SQL Server dropped) |
| DefectDojo | PostgreSQL (MySQL removed in 2.37) |
| Anchore Enterprise | PostgreSQL (17+ in 6.x) |
| Harbor | PostgreSQL for metadata, policies and audit logs |
| Grype (vulnerability DB) | SQLite file, distributed read-only |
| Sysdig Secure, Wiz | SaaS; storage not public |

Server products in this space standardize on **PostgreSQL**; SQLite is the norm for
embedded, single-process data (grype's own DB). This confirms the split: SQLite for the
CLI, CI jobs and single-node installs; PostgreSQL for production server deployments
(HA, managed backups, encryption at rest, FIPS endpoints on RDS).

**Proposed** (pending maintainer decision): given the production goal, pull PostgreSQL
support (issue #32) forward from M6 to M4, before server mode.

Sources: [Dependency-Track 5.0 announcement](https://owasp.org/blog/2026/06/09/dependency-track-v5),
[DefectDojo 2.37 upgrade notes](https://docs.defectdojo.com/releases/os_upgrading/2.37/),
[Anchore Enterprise requirements](https://docs.anchore.com/current/docs/deployment/requirements/),
[Harbor DB image description](https://hub.docker.com/hardened-images/catalog/dhi/harbor-db).
