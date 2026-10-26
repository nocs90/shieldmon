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

mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for pin in "${PINS[@]}"; do
  IFS='|' read -r platform name version url sha <<<"$pin"
  [[ "$platform" == "$PLATFORM" ]] || continue
  archive="$tmp/$name.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$archive" "$url"
  echo "$sha  $archive" | sha256sum --check --quiet - || { echo "checksum mismatch for $name $version" >&2; exit 1; }
  tar -xzf "$archive" -C "$tmp" "$name"
  install -m 0755 "$tmp/$name" "$DEST/$name"
  echo "installed $name $version ($PLATFORM) -> $DEST/$name (sha256 $(sha256sum "$DEST/$name" | cut -d' ' -f1))"
done
