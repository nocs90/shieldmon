# Enrichment

Enrichers add facts that scanners do not reliably report ([ADR 0019](../adr/0019-enrichers.md)).
`shieldmon plugins` lists them.

## CISA KEV

On by default: every finding whose vulnerability (or one of its aliases) is in the
[CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
is flagged KEV, whatever the scanners say. KEV findings raise `finding_new_kev`
notifications and are counted in reports.

- The catalog is refreshed with the vulnerability DBs: before each `monitor` cycle (when there
  are targets), before `scan` and `rematch`, and by `shieldmon db update`. Conditional
  requests make an unchanged catalog cost one round trip.
- Every scan applies the catalog, so a CVE CISA adds today is flagged on the next cycle.
- Data lives in `<data_dir>/enrich/kev/kev.json` (owner-only).

```yaml
enrichers:
  kev:
    max_age: 72h                                              # default
    options: { url: https://mirror.example.com/kev.json }    # an internal mirror
    # options: { file: /srv/feeds/known_exploited_vulnerabilities.json }   # a local copy
    # enabled: false
```

Hosts without internet access: copy the JSON feed regularly (it is public) and use `file:`,
or turn the enricher off.

## Health findings

| Check | Meaning | What to do |
|---|---|---|
| `enrichment_update_failed` | the source could not be read or its data was refused (truncated, malformed, much smaller than the data already known) | check access to the URL or the file; the previous data stays in use |
| `enrichment_stale` | the data was last confirmed longer ago than `max_age` | findings miss recent KEV additions until the update succeeds |
