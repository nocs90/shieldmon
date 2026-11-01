# 0012 — Container image: distroless, non-root, read-only, scanners pinned

- Status: accepted
- Date: 2026-10-26

## Context

- Operators need a ready image for Kubernetes CronJobs and similar (#7, #11), and the image
  is the natural place to enforce non-root and a read-only root filesystem.
- Scanners are a supply-chain target (CVE-2026-33634, ADR 0006): they must come pinned by
  checksum, as `scripts/install-scanners.sh` already does for linux/amd64. Nodes are
  increasingly arm64.
- Inside a container, bwrap cannot start: runtimes deny user namespaces. The `landlock`
  backend exists for this case (ADR 0011).
- ShieldMon writes only under its data dir, except that SQLite and Go's `os.TempDir` look
  for `/tmp`, which a read-only root filesystem does not have.
- The project rule is never to run image content: scanned images are hostile. ShieldMon's own
  image, built in the same CI job, is not scanned content, and only running it shows that it
  starts and that Landlock works under a container runtime.

## Decision

1. **Build.** A multi-stage `Dockerfile` for linux/amd64 and linux/arm64 without emulation:
   the build stages run on the build platform; Go cross-compiles with `CGO_ENABLED=0`, and
   `install-scanners.sh PLATFORM` downloads the target's scanners against checksums recorded
   in the script, which now has arm64 pins (from each release's checksums file, checked to
   list the amd64 hashes already pinned). `.dockerignore` sends only `cmd/`, `internal/`,
   the module files and the installer.
2. **Base.** `gcr.io/distroless/static-debian12:nonroot`: no shell, no package manager.
   Base images and the CI BuildKit image are pinned by digest; Renovate updates them.
3. **Layout.** `/usr/local/bin/{shieldmon,syft,grype,trivy}`; `/data` is the data dir, a
   volume owned by 65532; `TMPDIR=/data/tmp`, which ShieldMon now creates at startup; the
   optional config is `/config/shieldmon/config.yaml` (`XDG_CONFIG_HOME=/config`). The
   process runs as `65532:65532`; the entrypoint is `shieldmon --data-dir /data`, and the
   default command is `monitor`.
4. **Sandbox.** No bwrap in the image: the default `auto` selects `landlock`. It needs
   Landlock ABI ≥ 2 on the node (Linux ≥ 5.19) and a runtime seccomp profile that allows
   the `landlock_*` system calls; where either is missing, scans refuse to start and
   `shieldmon plugins` says why. Recommended pod settings: `runAsNonRoot`,
   `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities dropped,
   `seccompProfile: RuntimeDefault`, and `/data` on a volume, ideally a size-limited one
   (`deploy/scratch`).
5. **CI.** ci/image builds both platforms on every change and checks them without running
   them (`scripts/check-image.py`: user, entrypoint, `TMPDIR`, and four static ELF
   executables of the right architecture). It then runs the amd64 image as a deployment
   would (read-only root, all capabilities dropped, `no-new-privileges`, Docker's default
   seccomp profile, no network): `version`, and `plugins` must list `landlock` as
   available. On main, nightly and PRs labelled `run/integration`, the container scans a
   pinned image and the image itself with the real scanners under `landlock`, sharing one
   data volume so that the DBs are downloaded once. A public runner has about 14 GB of
   disk: on the first run, with the BuildKit cache still there, trivy's DB update hit the
   2 GiB free-disk floor, so the builder is removed after the push.
   This is the only image CI runs; the rule in CLAUDE.md says so.

## Consequences

- The smoke test covers Docker's default seccomp profile only. Other runtimes and
  Kubernetes pod settings are shown by the deployment examples (#11).
- Publishing to a registry, signing and provenance belong to the release pipeline (#8):
  `ghcr.io/nocs90/shieldmon:<version>`, signed by digest with cosign keyless signing, SLSA
  provenance in the registry (docs/processes/release.md). An SBOM of the image itself is not
  attested yet; the binaries' archives have one.
- The image is about the size of the three scanners. Bumping a scanner is a reviewed change
  to `install-scanners.sh` for both platforms.
- arm64 is built and checked, but no CI job scans with arm64 scanners.
