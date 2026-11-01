#!/usr/bin/env bash
# Install syft, grype and trivy at pinned versions, verifying each archive
# against a SHA-256 recorded in this file (not fetched at install time).
#
# Why: scanners run with access to image content and are a supply-chain
# target (e.g. the March 2026 trivy release/tag compromise, CVE-2026-33634).
# Bumping a version is a reviewed change to this file.
#
# Usage: scripts/install-scanners.sh [DEST_DIR] [PLATFORM]
#   DEST_DIR  default ./bin/scanners
#   PLATFORM  linux/amd64 or linux/arm64; default: this host. Give it to install for another
#             architecture: the container image build downloads for its target platform.
#   LICENSES  (environment) a directory to also install each scanner's LICENSE into, as
#             LICENSES/<scanner>/LICENSE: images that redistribute the binaries must carry it.
# Pins come from each release's checksums file; when bumping, check that the file also
# lists the hashes already recorded here for the previous version's other platform.
set -euo pipefail

DEST="${1:-./bin/scanners}"
PLATFORM="${2:-}"
if [[ -z "$PLATFORM" ]]; then
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64) PLATFORM=linux/amd64 ;;
    Linux/aarch64 | Linux/arm64) PLATFORM=linux/arm64 ;;
    *)
      echo "install-scanners: no pins for this host; pass linux/amd64 or linux/arm64, or install scanners manually and pin them in config" >&2
      exit 1
      ;;
  esac
fi

# platform|name|version|url|sha256
PINS=(
  "linux/amd64|syft|1.55.0|https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz|bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d"
  "linux/amd64|grype|0.119.0|https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_amd64.tar.gz|3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b"
  "linux/amd64|trivy|0.74.0|https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz|2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
  "linux/arm64|syft|1.55.0|https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_arm64.tar.gz|929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304"
  "linux/arm64|grype|0.119.0|https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_arm64.tar.gz|29f0ec7c549ddb0e2b6a0ca714851f7399438afc399b80c12808e065edc9a8f8"
  "linux/arm64|trivy|0.74.0|https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-ARM64.tar.gz|b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5"
)

if [[ "$(printf '%s\n' "${PINS[@]}" | grep -c "^$PLATFORM|")" -ne 3 ]]; then
  echo "install-scanners: no complete set of pins for $PLATFORM" >&2
  exit 1
fi

# Signatures (ADR 0006): each project signs its release's checksums file in GitHub Actions with
# Sigstore keyless signing. cosign verifies it against the exact workflow identity below before
# anything from the release is trusted; the archive must then be listed in that signed file
# with the SHA-256 pinned here. Two independent anchors: this file and the projects' signers.
OIDC_ISSUER=https://token.actions.githubusercontent.com
# name|certificate identity ({v}: the version)|signature material: bundle or sig+pem
SIGNERS=(
  "syft|https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main|bundle"
  "grype|https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main|sig+pem"
  "trivy|https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v{v}|bundle"
)
# cosign itself, pinned like the scanners (it runs on this host, whatever PLATFORM is).
COSIGN_VERSION=3.1.3
# host|sha256 of cosign-<os>-<arch> from cosign_checksums.txt
COSIGN_PINS=(
  "Linux/x86_64|4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71|linux-amd64"
  "Linux/aarch64|c5d324e091826b0d7a78eb16fef316450b4eb9aaec045611c08ba06f5e73220a|linux-arm64"
  "Darwin/arm64|5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76|darwin-arm64"
)

fetch() { curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$1" "$2"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

host="$(uname -s)/$(uname -m)"
[[ "$host" == Linux/arm64 ]] && host=Linux/aarch64
# COSIGN=/path/to/cosign uses a binary already there (a CI cache, a host whose firewall allows
# known binaries only), if it is the pinned one.
cosign=""
for pin in "${COSIGN_PINS[@]}"; do
  IFS='|' read -r h csha asset <<<"$pin"
  [[ "$h" == "$host" ]] || continue
  if [[ -n "${COSIGN:-}" ]]; then
    cosign="$COSIGN"
  else
    cosign="$tmp/cosign"
    fetch "$cosign" "https://github.com/sigstore/cosign/releases/download/v$COSIGN_VERSION/cosign-$asset"
    chmod 0700 "$cosign"
  fi
  [[ "$(sha256 "$cosign")" == "$csha" ]] || { echo "install-scanners: $cosign is not cosign $COSIGN_VERSION (checksum mismatch)" >&2; exit 1; }
done
[[ -n "$cosign" ]] || { echo "install-scanners: no cosign pin for $host: signatures cannot be verified" >&2; exit 1; }

verified=()
for pin in "${PINS[@]}"; do
  IFS='|' read -r platform name version url sha <<<"$pin"
  [[ "$platform" == "$PLATFORM" ]] || continue
  signer="$(printf '%s\n' "${SIGNERS[@]}" | grep "^$name|")" || { echo "install-scanners: no signer for $name" >&2; exit 1; }
  IFS='|' read -r _ identity material <<<"$signer"
  identity="${identity//\{v\}/$version}"
  base="${url%/*}"
  sums="$tmp/${name}_checksums.txt"
  fetch "$sums" "$base/${name}_${version}_checksums.txt"
  case "$material" in
    bundle)
      fetch "$sums.sigstore.json" "$base/${name}_${version}_checksums.txt.sigstore.json"
      sigargs=(--bundle "$sums.sigstore.json") ;;
    sig+pem)
      fetch "$sums.sig" "$base/${name}_${version}_checksums.txt.sig"
      fetch "$sums.pem" "$base/${name}_${version}_checksums.txt.pem"
      sigargs=(--signature "$sums.sig" --certificate "$sums.pem") ;;
  esac
  # Sigstore's TUF and Rekor are on the network: a transient failure is retried; a wrong
  # signature fails every attempt.
  ok=""
  for attempt in 1 2 3; do
    if out="$("$cosign" verify-blob "${sigargs[@]}" --certificate-identity "$identity" --certificate-oidc-issuer "$OIDC_ISSUER" "$sums" 2>&1)"; then
      ok=1
      break
    fi
    [[ "$attempt" == 3 ]] || sleep $((attempt * 5))
  done
  if [[ -z "$ok" ]]; then
    # cosign says why: a wrong signer, a changed file, or no access to Sigstore (TUF, Rekor).
    echo "install-scanners: signature of $name $version checksums not verified for $identity:" >&2
    printf '%s\n' "$out" | grep -v '^WARNING' | tail -3 >&2
    exit 1
  fi
  grep -qxF "$sha  ${url##*/}" "$sums" \
    || { echo "install-scanners: $name $version: the pinned SHA-256 is not in the signed checksums" >&2; exit 1; }
  archive="$tmp/$name.tar.gz"
  fetch "$archive" "$url"
  [[ "$(sha256 "$archive")" == "$sha" ]] || { echo "checksum mismatch for $name $version" >&2; exit 1; }
  tar -xzf "$archive" -C "$tmp" "$name"
  if [[ -n "${LICENSES:-}" ]]; then
    mkdir -p "$tmp/licenses/$name"
    tar -xzf "$archive" -C "$tmp/licenses/$name" LICENSE
  fi
  verified+=("$name|$version")
done

# All or nothing: DEST changes only once every scanner verified.
for v in "${verified[@]}"; do
  IFS='|' read -r name version <<<"$v"
  install -m 0755 "$tmp/$name" "$DEST/$name"
  if [[ -n "${LICENSES:-}" ]]; then
    mkdir -p "$LICENSES/$name"
    install -m 0644 "$tmp/licenses/$name/LICENSE" "$LICENSES/$name/LICENSE"
  fi
  echo "installed $name $version ($PLATFORM) -> $DEST/$name (signature verified, sha256 $(sha256 "$DEST/$name"))"
done
