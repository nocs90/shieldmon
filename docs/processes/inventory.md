# Inventory

Before looking at findings, an auditor or an incident responder asks what is monitored and
whether the evidence for it is fresh. `shieldmon report inventory` answers from the store
(epic #68).

```sh
shieldmon report inventory                                     # Markdown, to read
shieldmon report inventory -o csv --out reports/inventory.csv   # one row per image
shieldmon report inventory -o json                              # everything, for tools
```

Files are written 0600: an inventory says where weaknesses can be found.

## What each image shows

| Field | Meaning |
|---|---|
| `ref`, `platform` | the target: image reference and platform as added (`targets add`) |
| `digest`, `repository` | what the reference resolved to at the last cycle |
| `monitored_since`, `last_resolved` | when the target was added, when the tag was last resolved |
| `digest_changes` | how many times the tag moved to a new digest (rebuilds), from the append-only history |
| `last_scan`, `last_scan_kind`, `last_scan_status` | the last scan of the digest: `initial` (SBOMs generated) or `rematch`, and `complete`, `partial` or `failed` |
| `last_complete_scan` | the last scan in which every matcher succeeded: the last full evidence |
| `scanners` | tools of the last scan, with the build date of their vulnerability DB |
| `sboms` | stored SBOMs: generator, version, format and SHA-256 (`shieldmon sbom export` retrieves them) |
| `open_*` | open findings by severity on the digest |
| `gaps` | evidence gaps, below |
| `base`, `base_source`, `base_status`, `base_digest`, `newest_base_digest`, `newest_base_since`, `base_unmaintained` | what the image is built on and whether rebuilding helps ([base-images.md](base-images.md)) |

Targets resolving to the same digest share its scans, SBOMs and findings; the summary
counts each digest's findings once.

## Evidence gaps

| Gap | Meaning | What to do |
|---|---|---|
| `unresolved` | the reference never resolved to a digest | check the reference and registry access (`shieldmon health`) |
| `no_scan` | the digest was never scanned | run `shieldmon monitor` |
| `last_scan_partial` | a matcher failed in the last scan: absent findings are not proof of a fix | see the `matcher_failed` health finding |
| `last_scan_failed` | the last scan failed | see the health findings of the target |
| `stale_evidence` | no complete scan within 1.5 × `health.monitor_interval` | is `monitor` scheduled and succeeding? |
| `missing_sbom:GEN` | no SBOM from a generator a configured matcher needs | the next scan generates it; persistent → `sbom_generator_failed` |

An image without gaps has a complete scan within the expected cadence, with every required
SBOM: its findings are current evidence.

## One BOM for everything monitored

```sh
shieldmon report inventory -o cyclonedx --out reports/inventory.cdx.json
```

A single CycloneDX 1.6 BOM (valid against the official schema): each monitored digest is a
`container` component (SHA-256 hash, `pkg:oci` package URL with repository and
architecture, and the tag when only one target uses the digest; every target as a
`shieldmon:target` property) with its components nested, read from the stored SBOMs under
the same integrity checks as `components`. Retired and unresolved images are left out; an
SBOM that cannot be read is a warning. Beyond 500,000 components the export refuses: use
`shieldmon sbom export` per image.

## Changes over a period

```sh
shieldmon report inventory --month 2026-10        # inventory now, plus October's changes
shieldmon report monthly --month 2026-10 -o html  # the monthly report has the same section
```

For the month: images **added** (targets created), **rebuilt** (the tag moved to a new
digest: old → new, with the first scan of the new digest for that image as evidence, or
"not scanned yet"), **retired** and **restored** (with who and why). Everything comes from
append-only history (`target_digests`, `target_events`, scans), so the changes of a past
month are the same whenever they are computed. In `md` and `json`; `csv` has one row per
image and refuses `--month`.

## Retiring an image

When an image is decommissioned, retire its target instead of leaving it monitored:

```sh
shieldmon targets retire 7 --reason "decommissioned in CHG-2041"   # --by defaults to $SHIELDMON_ACTOR or $USER
shieldmon targets restore 7 --reason "back in production"
```

- Retirement is recorded append-only with who and why; `monitor` skips the target and
  `scan` refuses it; `targets add` of the same image points to `restore`.
- **Findings are not closed**: nothing proved them fixed ([ADR 0017](../adr/0017-target-retirement.md)).
  A finding whose images are all retired is *retired with the image*: out of open counts,
  burndown, SLA breaches and notifications, counted apart in the monthly report. If another
  monitored target still resolves to the same digest, its findings stay in scope.
- The inventory keeps listing retired images with their retirement date, without gaps or
  open counts. Restoring puts everything back as it was; the next cycle rescans.

## Components: what the images contain

During an incident the question is "where do we run this package?". The SBOMs stored at scan
time already answer it, without pulling or scanning anything:

```sh
shieldmon components where xz-libs@5.6.0             # NAME@VERSION
shieldmon components where pkg:apk/alpine/openssl    # a package URL: every version
shieldmon components where log4j-core -o json        # NAME (GROUP/NAME for Maven)
shieldmon components list --target registry.example.com/app:prod -o csv
```

- `where` exits 1 when no monitored image contains the package, for scripts.
- Components come from the CycloneDX SBOMs of each image's **current** digest (all
  generators merged, deduplicated by package URL), with their licenses when the SBOM has them.
- Each SBOM is checked against the size and SHA-256 recorded when it was generated, inside
  the data directory and not through a symlink; one that fails is reported as a warning and
  not used: it is no longer the evidence the scan produced.
- Reading is bounded (64 MiB, 100,000 components, nesting depth 16 per SBOM); SBOMs describe
  image content and are treated as hostile input.
