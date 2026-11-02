# Releases

A release is a signed tag; [.github/workflows/release.yml](../../.github/workflows/release.yml)
builds and signs everything, and leaves a draft for a maintainer to publish.

## Steps

1. The milestone's definition of done passes in CI on `main` (including `ci/image`, which
   scans and gates ShieldMon's own image); open issues are moved or closed.
2. Update the SPEC status column and ROADMAP in a PR; breaking changes are in PR titles
   (`feat!:` / `fix!:`), which the changelog groups first.
3. Tag `main` with a signed tag and push it:

   ```sh
   git tag -s v0.4.0 -m "v0.4.0" && git push origin v0.4.0
   ```

   Only repository admins can create `v*` tags, and nobody can move or delete one (rulesets,
   [quality-gates.md](quality-gates.md#repository-settings-maintainer-checklist)): check the
   commit before pushing. A release candidate is `v0.4.0-rc.1`; a broken release is fixed by
   the next version, never by re-tagging.

   A release candidate may be tagged on a release branch (`release/v0.4.0`) to try the
   pipeline, and a fix it needs reaches `main` through a pull request; the release itself must
   point to a commit of `main`, or the workflow stops before building anything.

4. The workflow runs two jobs:
   - **binaries**: goreleaser (pinned, v2.18.3) builds `shieldmon` for linux and darwin, amd64
     and arm64, reproducibly (`-trimpath`, no build ID, timestamps from the commit), archives
     them with LICENSE, README, SECURITY and THIRD_PARTY_LICENSES (the license texts of every
     linked Go module, written by `scripts/third-party-licenses.sh`, which fails on a module
     without one), writes `shieldmon_<v>_checksums.txt` and a
     CycloneDX SBOM of each archive (syft, installed signature-verified by
     `scripts/install-scanners.sh`), signs the checksums with cosign keyless signing
     (`shieldmon_<v>_checksums.txt.sigstore.json`), creates the draft release, and attaches
     SLSA build provenance to the archives and checksums (GitHub artifact attestations).
   - **image**: builds `ghcr.io/nocs90/shieldmon:<v>` for linux/amd64 and linux/arm64, signs
     it by digest with cosign keyless signing, and pushes its provenance to the registry. The
     image carries ShieldMon's license and its modules' under `/usr/share/licenses/shieldmon`,
     and each bundled scanner's under `/usr/share/licenses/<scanner>`.
5. Read the draft's notes, check the assets, publish it, and announce it in Discussions with
   breaking changes called out.

Versioning: SemVer; pre-1.0 minors may break configuration and JSON output.

## Verifying a release

The signer is the release workflow of this repository at that tag; nothing else is trusted.

```sh
v=0.4.0
id="https://github.com/nocs90/shieldmon/.github/workflows/release.yml@refs/tags/v$v"
iss=https://token.actions.githubusercontent.com

# Binaries: the signed checksums cover every archive and SBOM.
cosign verify-blob --bundle shieldmon_${v}_checksums.txt.sigstore.json \
  --certificate-identity "$id" --certificate-oidc-issuer "$iss" shieldmon_${v}_checksums.txt
sha256sum --check --ignore-missing shieldmon_${v}_checksums.txt
gh attestation verify shieldmon_${v}_linux_amd64.tar.gz --repo nocs90/shieldmon   # SLSA provenance

# Container image: by digest, never by tag.
cosign verify ghcr.io/nocs90/shieldmon@sha256:<digest> \
  --certificate-identity "$id" --certificate-oidc-issuer "$iss"
gh attestation verify oci://ghcr.io/nocs90/shieldmon@sha256:<digest> --repo nocs90/shieldmon
```

Deploy the image by the verified digest (`deploy/kubernetes/kustomization.yaml`, `images:`).

## Reproducing a build

The archives of a tag can be rebuilt from its commit and compared with the published
checksums:

```sh
git checkout v$v
goreleaser release --snapshot --clean --skip=sign,sbom,publish   # goreleaser v2.18.3, Go from go.mod
```

Two builds of the same commit give byte-identical archives (checked when the pipeline was
added: same checksums for all four archives). A snapshot's version string differs from the
tag's, so compare a build made with the tag checked out and `goreleaser release
--skip=sign,sbom,publish --clean`, or compare the binaries inside the archives.
