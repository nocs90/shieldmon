# 0025 — Successor bases: configured, followed, never guessed

- Status: accepted
- Date: 2026-10-30

## Context

- When a base is unmaintained (ADR 0022) a rebuild fixes nothing; the image needs another
  lineage. In the UBI 9 e2e scenario `ubi9/nodejs-20-minimal` (Node 20 end of life) was
  succeeded by `ubi9/nodejs-22-minimal`; nothing in the registry links the two (#41).
- Guessing a successor from tag or repository names (`20` → `22`) is wrong as often as it is
  right: `-minimal` vs full, LTS vs current, distribution moves (`ubi8` → `ubi9`), renamed
  repositories.
- End-of-life data exists for products (endoflife.date: product, cycle, EOL date), not for
  images: mapping an image to a product cycle is the same guess, plus a network source
  outside the vulnerability DBs.

## Decision

- Successors are **configured**: `bases.successors`, a list of `from` (a reference pattern
  over base references, ADR 0024 syntax) and `to` (a tag reference); the first match wins.
  Patterns and references are validated at startup.
- ShieldMon follows each successor in use like a base: resolved once per monitoring cycle,
  recorded when it moves (`base_observations`), so its freshness is known the same way
  (observed, or a plausible `created`). No SBOM is generated for it and nothing is matched.
- The inventory, the monthly report and `base_unmaintained` notifications name the successor
  and since when it points to its current digest.
- No end-of-life feed now: an enricher could add one later (ADR 0019) once a mapping from
  images to product cycles is configured, not inferred.

## Consequences

- The successor list is curated by the platform team, like owners and bases; a stale entry
  shows as a successor that is itself old.
- One more manifest request per cycle per successor in use.
