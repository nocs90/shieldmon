# 0022 — Base image lineage: what an image is built on, proven by its layers

- Status: accepted
- Date: 2026-10-29

## Context

- Most container fixes are a rebuild on a newer base, and a rebuild fixes nothing when the
  base itself is no longer maintained. In the UBI 9 + Node.js e2e scenario the newest
  `ubi9/nodejs-20-minimal` was five months old and left ~250 findings that already had an
  upstream fix, while `ubi9/nodejs-22-minimal` had been rebuilt two weeks earlier (#41).
- The OCI image spec defines the `org.opencontainers.image.base.name` and
  `org.opencontainers.image.base.digest` annotations; the base "SHOULD be the immediate image
  sharing zero-indexed layers with the image". BuildKit does not set them by default: they
  are there only when a build sets them (`--output annotation.…`), and nothing checks them.
- Labels are inherited from the base unless overridden: a `name=ubi9/nodejs-20-minimal`
  label in an image says nothing about whether the image or its base set it.
- Reproducible images set the config `created` time to the epoch (distroless) or to the
  source date (`SOURCE_DATE_EPOCH`): it is not when the base was published.

## Decision

**Base reference.** In order of trust: the base configured for the target
(`targets add --base REF`, `targets set-base TARGET REF|--none`, recorded append-only with the
actor), then the `org.opencontainers.image.base.name` annotation of the platform manifest
(else of its index descriptor). Labels and tag-name heuristics are never used.

**Base digest, proven by layers.** A digest is the image's base only when its config
`rootfs.diff_ids` are a prefix of the image's. Candidates are the digests the base reference
has been seen pointing to, and the `base.digest` annotation, which is fetched and checked
like any other candidate: an annotation is a claim until its layers match.

**When the registry is read.** Manifests and configs only, bounded like every registry
response; no layer is pulled and no scanner sees a base image.

- Each image digest is inspected once, when it is first scanned: its diff_ids and base
  annotations are stored. Annotation values longer than 512 bytes, or not a valid reference or
  `sha256:` digest, are ignored and reported.
- Each base reference is resolved once per monitoring cycle and platform (and when a target
  using it is scanned); a new digest is inspected and recorded append-only
  (`base_observations`, like `target_digests`). Configured bases (`target_bases`), image
  inspections (`image_inspections`) and observations are append-only tables of schema v7,
  sealed in the audit chain (ADR 0018). Failing to resolve or inspect a base opens a
  `base_resolve_failed` health finding: missing evidence is a monitoring failure (I6).

**Status of an image**, computed from those records, never stored:

| Status | When |
|---|---|
| `current` | the newest digest of the base reference is a layer prefix of the image |
| `rebuild_available` | an older digest of the base reference (or the annotated, verified base digest) is the prefix, and the reference now points elsewhere |
| `unknown` | a base reference is known but no observed or annotated digest is a prefix |
| `none` | no base reference is configured or annotated |

`base_unmaintained`: the base reference has pointed to its current digest for longer than
`bases.max_age` (default 90 days). That time starts at the first observation of the current
digest; when ShieldMon has never seen the reference change, at the config `created` time if it
is after 2000-01-01 and not in the future, else unknown until observed for `max_age`.

These are properties of the image, shown in the inventory, the monthly report and as
notification events; they are not health findings and change no finding state.

## Consequences

- An image is never said to be on a base it does not share layers with; a wrong annotation
  or a wrong configured base shows as `unknown`, not as a false "current".
- Images built with `docker build` and no annotation need a configured base; `targets add
  --base` makes it part of onboarding.
- The age of a base is never overstated from a reproducible `created` time; until ShieldMon has
  watched a reference change, the age can be unknown.
- One manifest request per base reference and platform per cycle, and a config read when it
  moves: bases shared by many images cost one lookup.
- Fixable-by-rebuild per finding needs the newest base's own findings (#41 follow-up); it
  builds on these records.
