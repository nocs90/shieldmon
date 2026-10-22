# 0007 — Normalization and cross-scanner deduplication

- Status: accepted
- Date: 2026-10-20

## Context

Grype and Trivy report the same issue with different PURL qualifiers
(`distro=alpine-3.18.0` vs `distro=3.18.0`, `package-id=…`), different ID schemes (GHSA vs
CVE, distro advisories), different severities and different fix-version formats.

## Decision

- **Canonical PURL**: parsed with packageurl-go; type lowercased; per-type name rules
  (PyPI PEP 503; lowercase for npm/apk/deb/gem); qualifiers dropped except `epoch`;
  subpath dropped. `pkg_key` = canonical PURL without version (lineage).
- **Canonical vulnerability ID**: `CVE-` uppercased, `GHSA-` prefix + lowercase body.
  A non-CVE ID is replaced by a CVE only when the union of its aliases across scanners
  names **exactly one** CVE; multi-CVE advisories stay distinct (collapsing them would
  hide CVEs). Original IDs are kept as aliases.
- **Merge** per (PURL, ID): severity and CVSS take the maximum, EPSS max, KEV OR,
  fix versions and scanners unioned.

## Consequences

- Conservative: when unsure we keep two findings rather than hide one.
- Unparseable PURLs fall back to `pkg:<type>/<name>@<version>` so nothing is dropped.
