# 0027 — Exporters: hand monitoring results to portfolio tools, keep closure here

- Status: accepted
- Date: 2026-10-31

## Context

- ADR 0001: integrate with portfolio tools instead of rebuilding their UIs. Teams already run
  OWASP Dependency-Track (component analysis per project, from CycloneDX BOMs) and DefectDojo
  (findings across tools, per product and engagement) (#34).
- Dependency-Track takes a BOM per project: `POST /api/v1/bom` (multipart: `autoCreate`,
  `projectName`, `projectVersion`, `bom`), API key in `X-Api-Key`.
- DefectDojo imports findings files: `POST /api/v2/reimport-scan/` (multipart: `scan_type`,
  `file`, `product_name`, `engagement_name`, `product_type_name`, `auto_create_context`,
  `test_title`, `close_old_findings`), API key in `Authorization: Token`. Its
  "Generic Findings Import" JSON has `title`, `severity` (`Critical`…`Info`) and `description`
  required, a fixed set of optional fields, and refuses unknown keys.
- Both are outbound HTTP with a credential, like notifiers (ADR 0015).

## Decision

- An **Exporter** extension point (`internal/export`): interface, registry, conformance kit
  (`exporttest`), configured under `exports:` with `*_env` options for credentials, like
  notifiers. It reuses the notifiers' hardened HTTP helpers: https only (http to localhost),
  no redirect followed, bounded answers, errors naming host and status only, redaction.
- `shieldmon export [NAME…]` sends the current state of every monitored target; schedule it
  after `monitor`. `--dry-run DIR` writes the payloads instead.
- **dependency-track**: one project per target, `projectName` the repository and
  `projectVersion` the tag (with the platform when the reference is monitored on several),
  `autoCreate`; the BOM is the stored syft CycloneDX SBOM of the current digest, as is.
- **defectdojo**: one product per repository (`product_type` option, default
  "Container images"), engagement "ShieldMon", one test per target (`test_title` = the target),
  reimported with `close_old_findings`: a finding ShieldMon closed by scan evidence closes in
  DefectDojo at the next export. Open and risk-accepted findings are sent (`risk_accepted`
  true for the latter); not_affected are not weaknesses and are not sent. Each finding's
  `unique_id_from_tool` is its problem (vulnerability and package, without version), stable
  across rebuilds; text fields are cut to DefectDojo's limits.
- Exports change nothing in ShieldMon. A failing exporter opens an `export_failed` health
  finding (subject: the export), resolved by the next success (I6).

## Consequences

- Closure stays evidence-based in ShieldMon; the portfolio tools mirror it. Decisions taken
  in DefectDojo or Dependency-Track do not flow back: record them in ShieldMon.
- Large fleets send one request per target and exporter; the per-registry rate limit does
  not apply (these are not registries): the tools' own limits do.
- The helpers stay in `internal/notify` while two packages use them.
