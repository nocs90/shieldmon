# 0019 — Enrichers: scanner-independent facts, refreshed with the vulnerability DBs

- Status: accepted
- Date: 2026-10-29

## Context

- Whether a finding is in the CISA Known Exploited Vulnerabilities catalog drives
  notifications (`finding_new_kev`), reports and, next, the priority score (#22). Until now
  ShieldMon only knew it when grype said so: trivy does not report it, and grype's copy is as
  fresh as its DB (#21).
- Other facts will follow the same shape (EPSS, vendor advisories): data fetched from a
  source on a schedule, looked up for every match.

## Decision

1. **Extension point**: `enrich.Enricher` (`Update`, `UpdatedAt`, `Enrich`), registered with
   `enrich.Register`, configured under `enrichers.<name>`, listed by `shieldmon plugins`,
   proven by `enrichtest.CheckEnricher` (ADR 0008).
2. **Update with the DBs**: enrichers update in the same step as the matchers' DBs (preflight
   of `monitor`, `scan`, `rematch`, and `shieldmon db update`), in the ShieldMon process, which
   never handles image content. A failed update keeps the data in use and opens
   `enrichment_update_failed`; data older than `max_age` (default 72h) opens
   `enrichment_stale`.
3. **Enrich every scan**: matches are enriched after normalization and before
   reconciliation, so existing findings follow the data at the next cycle (a CVE added to KEV
   is flagged then). Enrichment only adds facts (KEV is never cleared by an enricher).
4. **KEV enricher, on by default**: the CISA JSON feed over HTTPS (redirects: https only, at
   most 3), conditional requests (ETag, Last-Modified), at most 32 MiB and 200,000 entries,
   CVE IDs and dates validated; a catalog with more than 10% malformed entries, a `count`
   that disagrees with its entries, or fewer than half the entries already known (KEV entries
   are almost never removed) is refused. A mirror URL or a local file serves hosts without
   internet access.
5. **Cache outside the scanners' reach**: `<data_dir>/enrich/<name>`, owner-only, written
   atomically — not under `<data_dir>/cache`, which scanner processes may write while
   updating their DBs.

## Consequences

- KEV is consistent across scanners and as fresh as the catalog.
- Air-gapped installations must provide the catalog (`file:` option) or turn the enricher off;
  otherwise the health findings say so.
- A KEV flag set by a scanner or an earlier catalog stays: removals from the catalog are rare
  and are not tracked.
