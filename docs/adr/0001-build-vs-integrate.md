# 0001 — Build the ConMon core, integrate everything around it

- Status: accepted
- Date: 2026-10-20

## Context

Prior art reviewed against the mission (scan → SBOM → tracked findings → evidence-based
closure → monthly lifecycle reporting, digest identity, policy-driven remediation deadlines):

| Project | Covers well | Gap vs. mission | Verdict |
|---|---|---|---|
| OWASP Dependency-Track | SBOM portfolio, continuous re-analysis of uploaded SBOMs, policy, VEX | Project/version identity rather than image digest lineage; no registry monitoring or tag→digest tracking; closure is a re-analysis side effect, not evidence from a successor digest; no self-health findings; no remediation-plan export | Integrate: export CycloneDX SBOMs to it (M4+) |
| DefectDojo | Aggregation of many scanners, dedupe, SLAs, reporting, risk acceptance | Import-driven (no SBOM-first rematch, no registry), closure on re-import semantics, heavy Django deployment | Integrate: generic findings export (M5) |
| Trivy Operator | In-cluster continuous scanning via CRDs | No history/lifecycle, no MTTR, cluster-scoped, no SBOM-first rematch of registry images | Out of scope; may ingest its reports later |
| Copacetic | Patching OS packages in images without rebuild | Not a monitoring tool | Integrate for remediation proposals (M7) |
| Renovate | Dependency/base-image bump PRs | Not vulnerability-driven, no ConMon | Reuse its approach for MR drafts (M7) |

None of them owns the core invariants (digest identity, evidence-based closure across
successor digests, self-health as findings, compliance-grade audit trail).

## Decision

Build the core (identity, lifecycle, evidence, audit, reporting) in ShieldMon. Do not
rebuild scanners, SBOM generators, patchers or portfolio UIs: wrap Syft, Grype and Trivy;
export to Dependency-Track and DefectDojo; use Copacetic for patch proposals.

## Consequences

- Our code is the state machine, the data model and the safety rails — small and testable.
- We depend on scanner output formats; adapters are pinned to versions and covered by
  fixture tests from real output.
