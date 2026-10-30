# 0023 — Fixable by rebuild: compare the image's base packages with the newest base

- Status: accepted
- Date: 2026-10-30

## Context

- ADR 0022 says whether an image is on the newest digest of its base tag. Teams then ask,
  finding by finding: does rebuilding remove it, does it need a different base, or is it in
  our own layers (#41)?
- Matching the newest base with the vulnerability scanners and storing its findings would
  mix findings of images nobody runs into every count, report and notification; keeping
  them apart would touch every query. Its matches would also come from a DB of another day
  than the image's.
- Generators record where a package was found: syft writes `syft:location:N:layerID` and
  trivy `aquasecurity:trivy:LayerDiffID` properties on CycloneDX components, with the
  uncompressed layer digest (diff ID); grype's matches carry the same layer IDs. They do not
  mean the same thing. In `python:3.12-alpine3.20` (4 layers, syft 1.55, trivy 0.67) syft
  puts all 36 apk packages in layer 3, the image's own `apk add` that rewrote
  `/lib/apk/db/installed`; trivy puts 14 in layer 1 (Alpine), 2 in layer 2 and 20 in layer 3:
  the layer that added each package.
- A package version is a fact of the SBOM; whether a version fixes a vulnerability is the
  scanners' job, done when the rebuilt image is scanned.

## Decision

Each open finding of an image with a proven base (ADR 0022) gets a **remedy**, computed when a
report is made, from stored SBOMs only:

| Remedy | When |
|---|---|
| `application` | the package is found only in layers above the base (the image's own layers) |
| `rebuild` | the package comes from base layers, and the newest digest of the base tag has another version of it, or none: a rebuild replaces it; the scan of the rebuilt image proves whether that fixes the finding |
| `base` | the package comes from base layers, and the newest base has the same version: a rebuild changes nothing; it needs a base that fixes it (another lineage, the vendor) |
| `unknown` | no layer of the package is recorded, the base is not proven, or the newest base has no SBOM yet |

- Base layers are the image's first layers that the proven base digest shares (ADR 0022);
  a package is in them when one of the layers any generator recorded for it is (the layers of
  all generators are merged per package before deciding). Packages are compared by canonical
  PURL without version (ADR 0007), versions as recorded. For a verified annotated base digest
  that was never observed, its layer count is recorded with the inspection (schema v8,
  `image_inspections.annotated_base_layers`).
- Layer properties in SBOMs are hostile input like the rest: only `sha256:` digests of 64 hex
  characters are kept, at most 16 per component (fuzzed).
- The newest base digest of each base tag in use gets SBOMs once, through the same SBOM-first
  path as images (limits, digest-verified fetch, sandboxed generators, validated, stored with
  SHA-256), when it is first observed. It is recorded as an artifact without a target: no
  matcher runs on it, it has no findings and is in no count.
- Remedies change no finding state; the closure of a finding stays with the scan of the
  rebuilt image (I4).

## Consequences

- "Rebuild" is an expectation, not a fix: a newer version can still be vulnerable. Reports
  word it so, and the next scan settles it.
- One image fetch and one SBOM generation per new base digest: bases move far less often than
  the images built on them, and are shared.
- Generators that record no layers leave findings `unknown`; both built-in generators record
  them. With syft alone, OS packages of a base under an image that installs packages would
  look like the application's: trivy's SBOM is what places them (both run by default).
- Checked on `python:3.12-alpine3.20` with `alpine:3.20` as base: 55 open findings `rebuild`
  (openssl, musl, busybox, zlib: the newest Alpine 3.20 ships newer versions), 68
  `application` (python, pip, sqlite installed by the image).
- Reports read stored SBOMs: bounded and parsed like any SBOM (hostile input).
