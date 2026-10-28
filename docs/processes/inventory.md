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
