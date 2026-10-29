# Base images: is a rebuild enough?

Normative rules: [ADR 0022](../adr/0022-base-image-lineage.md). This page is the runbook.

Most findings in an image come from its base (the image its Dockerfile starts `FROM`). Two
questions decide what to do with them:

- **Is a newer base available?** Then rebuilding the image fixes what the base fixed.
- **Is the base still maintained?** When the base tag has not moved for months, rebuilding
  fixes nothing: the image needs another base (`nodejs-20-minimal` → `nodejs-22-minimal`).

## Telling ShieldMon the base

```sh
shieldmon targets add ghcr.io/org/api:2.1 --base registry.access.redhat.com/ubi9/nodejs-22-minimal:latest
shieldmon targets set-base 7 docker.io/library/alpine:3.20      # an existing target
shieldmon targets set-base 7 --none                              # forget it
shieldmon targets list                                           # BASE column
```

The base is the **tag** the build follows, as in its `FROM` line; a digest never moves, so it is
refused. Every change is recorded with who made it (`--by`, default `$SHIELDMON_ACTOR` or
`$USER`).

Without a configured base, ShieldMon uses the image's `org.opencontainers.image.base.name`
annotation, which builds set explicitly, for example with BuildKit:

```sh
docker buildx build \
  --output "type=image,name=ghcr.io/org/api:2.1,push=true,annotation.org.opencontainers.image.base.name=registry.access.redhat.com/ubi9/nodejs-22-minimal:latest" .
```

A configured base wins over the annotation. Labels and tag names are never used: they do not
say which image is the base.

## How it is proven

ShieldMon reads only manifests and configs (no layer is pulled, no scanner runs):

- each new image digest once: its layer list (`rootfs.diff_ids`) and base annotations;
- each base tag once per monitoring cycle, and its layer list when the tag moved. Every digest
  the tag points to is recorded (append-only, in the audit chain).

An image is on a base digest only if that digest's layers are the first layers of the image.
An annotated `org.opencontainers.image.base.digest` is checked the same way before it counts.

## What the inventory shows

`shieldmon report inventory` (Markdown section "Base images"; `base_*` columns in CSV, `base`
in JSON):

| Status | Meaning | What to do |
|---|---|---|
| `current` | the image is built on the newest digest of its base tag | nothing for the base: remaining findings need the base vendor or the application |
| `rebuild_available` | the image is built on an older digest of the base tag | rebuild and push the image (Renovate/Dependabot can do it on base updates); the next cycle shows it `current` and closes what the new base fixed, with scan evidence |
| `unknown` | a base is named but no digest it pointed to shares the image's layers | the configured base is wrong, the image was built from a mirror or a pinned digest older than ShieldMon's observations, or the base has not been resolved yet (`base_resolve_failed`) |
| `none` | no configured or annotated base | `targets set-base` |

`base_unmaintained` (and `Unmaintained base` in Markdown): the base tag has pointed to the same
digest for longer than `bases.max_age` (default 90 days). The time counts from when ShieldMon
saw the tag move; for a tag it has never seen move, from the base's creation time, unless that
is not plausible (reproducible images set the epoch), in which case only what ShieldMon
observed counts. Rebuilding on an unmaintained base fixes nothing: plan a migration to a
maintained lineage.

```yaml
bases:
  max_age: 2160h   # 90 days; 0 disables
```

A base that cannot be resolved opens a `base_resolve_failed` health finding: the statuses then
rest on older observations.
