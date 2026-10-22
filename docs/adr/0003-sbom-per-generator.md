# 0003 — One SBOM per (digest, generator); matchers consume their own generator's SBOM

- Status: accepted
- Date: 2026-10-20

## Context

The design calls for "SBOM once per digest, re-match daily". Measured on
`alpine:3.18.0` (2026-10-20, syft 1.55.0, grype 0.119.0, trivy 0.74.0):

| Matcher input | Matches |
|---|---|
| grype on syft CycloneDX | 63 |
| trivy on **syft** CycloneDX | **6** |
| trivy on trivy CycloneDX | 49 |

Trivy loses the distro source-package mapping when reading a foreign SBOM. A single
shared SBOM would silently drop most of trivy's findings — and the dedupe would then
report them as "grype-only", making the two-scanner setup look like it adds coverage
when it does not.

## Decision

- Each matcher declares its generator: grype ← syft, trivy ← trivy.
- On first sight of a digest, ShieldMon fetches the image **once** into a temporary,
  digest-verified OCI layout and runs every required generator against it.
- syft emits CycloneDX (primary) and SPDX; trivy emits CycloneDX.
- Re-matching uses stored SBOMs only; the registry is contacted just to resolve the tag.

## Consequences

- Two SBOMs per digest (small: tens of KB each for typical images).
- Adding a matcher means declaring which SBOM it is validated against, with a fixture
  test showing parity.
- `TestRealOutputsDeduplicate` and the integration test guard against regressions.
