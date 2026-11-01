#!/usr/bin/env bash
# Write the license texts of every Go module linked into shieldmon, for the release archives
# and the container image: binary redistribution must carry them (MIT, BSD, Apache-2.0 NOTICE).
#
# Usage: [PLATFORMS="linux/amd64 darwin/arm64 ..."] scripts/third-party-licenses.sh [OUT]
#   OUT        default THIRD_PARTY_LICENSES
#   PLATFORMS  the builds to cover (dependencies differ per OS); default: GOOS/GOARCH.
# Needs the module cache (go mod download). Fails when a module has no license file, so that
# a dependency without a known license cannot ship unnoticed.
set -euo pipefail

out="${1:-THIRD_PARTY_LICENSES}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

# Module path, version and directory of every non-main module in the builds of shieldmon.
platforms="${PLATFORMS:-$(go env GOOS)/$(go env GOARCH)}"
for p in $platforms; do
  GOOS="${p%/*}" GOARCH="${p#*/}" go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/shieldmon
done | sort -u > "$tmp"

{
  echo "Third-party software linked into ShieldMon, with its license texts."
  echo "ShieldMon itself is licensed under the GNU AGPL-3.0 (LICENSE)."
  echo
  missing=0
  n=0
  while read -r path version dir; do
    n=$((n + 1))
    files=()
    while IFS= read -r f; do files+=("$f"); done < <(find "$dir" -maxdepth 1 -type f \
      \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | LC_ALL=C sort)
    if [[ ${#files[@]} -eq 0 ]]; then
      echo "third-party-licenses: no license file in $path $version" >&2
      missing=1
      continue
    fi
    echo "================================================================================"
    echo "$path $version"
    echo "================================================================================"
    for f in "${files[@]}"; do
      echo "--- ${f##*/}"
      cat "$f"
      echo
    done
  done < "$tmp"
  [[ "$missing" == 0 ]] || exit 1
  echo "wrote $out ($n modules)" >&2
} > "$out"
