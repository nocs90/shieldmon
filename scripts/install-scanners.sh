#!/usr/bin/env bash
# Install syft, grype and trivy at pinned versions, verifying each archive
# against a SHA-256 recorded in this file (not fetched at install time).
#
# Why: scanners run with access to image content and are a supply-chain
# target (e.g. the March 2026 trivy release/tag compromise, CVE-2026-33634).
# Bumping a version is a reviewed change to this file.
#
# Usage: scripts/install-scanners.sh [DEST_DIR]   (default: ./bin/scanners)
# Supported: linux/amd64. Other platforms: add pins below.
set -euo pipefail

DEST="${1:-./bin/scanners}"

# name|version|url|sha256
PINS=(
  "syft|1.55.0|https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_amd64.tar.gz|bb65249542db5fedeeb4d3f9b018b75e7264dbfbbb10486f044581a92f90490d"
  "grype|0.119.0|https://github.com/anchore/grype/releases/download/v0.119.0/grype_0.119.0_linux_amd64.tar.gz|3fa2dc4b924621ab65404cf08d0b8438d896d80ab949c9d5a4ca283c36004c9b"
  "trivy|0.74.0|https://github.com/aquasecurity/trivy/releases/download/v0.74.0/trivy_0.74.0_Linux-64bit.tar.gz|2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
)

if [[ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]]; then
  echo "install-scanners: only linux/amd64 pins are recorded; install scanners manually and pin them in config" >&2
  exit 1
fi

mkdir -p "$DEST"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for pin in "${PINS[@]}"; do
  IFS='|' read -r name version url sha <<<"$pin"
  archive="$tmp/$name.tar.gz"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$archive" "$url"
  echo "$sha  $archive" | sha256sum --check --quiet - || { echo "checksum mismatch for $name $version" >&2; exit 1; }
  tar -xzf "$archive" -C "$tmp" "$name"
  install -m 0755 "$tmp/$name" "$DEST/$name"
  echo "installed $name $version -> $DEST/$name (sha256 $(sha256sum "$DEST/$name" | cut -d' ' -f1))"
done
