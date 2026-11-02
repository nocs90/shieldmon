#!/usr/bin/env bash
# Install syft, grype and trivy at pinned versions, and helm (which renders charts), verifying
# each archive against a SHA-256 recorded in this file (not fetched at install time) and its
# project's release signature.
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
#   HELM      (environment) 0 skips helm: only chart rendering needs it, and verifying it needs gpg.
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
  "linux/amd64|grype|0.121.0|https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_amd64.tar.gz|64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519"
  "linux/amd64|trivy|0.76.1|https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-64bit.tar.gz|c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"
  "linux/arm64|syft|1.55.0|https://github.com/anchore/syft/releases/download/v1.55.0/syft_1.55.0_linux_arm64.tar.gz|929bd163db2d7cd2255d3bcb8967208079813d7b46b0c952f7b794d8e2c7d304"
  "linux/arm64|grype|0.121.0|https://github.com/anchore/grype/releases/download/v0.121.0/grype_0.121.0_linux_arm64.tar.gz|86f570f75ca947ea3dd6486309232bcff6d78e44ba081ae75ab14eab72be3dae"
  "linux/arm64|trivy|0.76.1|https://github.com/aquasecurity/trivy/releases/download/v0.76.1/trivy_0.76.1_Linux-ARM64.tar.gz|e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"
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
  "grype|https://github.com/anchore/grype/.github/workflows/release.yaml@refs/heads/main|bundle"
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

# helm renders third-party charts (ADR 0033), in the scanners' sandbox. Helm signs each release
# archive with OpenPGP, not Sigstore: the signature must be valid and made by the pinned
# release key, taken from Helm's KEYS file at a pinned commit, itself pinned by SHA-256.
HELM_VERSION=4.3.1
# platform|sha256 of helm-v<version>-linux-<arch>.tar.gz (its .sha256sum on get.helm.sh)
HELM_PINS=(
  "linux/amd64|0403a88ae20913d11b10a2467b50087721fea7581736da6b9d3992f5357fe54b"
  "linux/arm64|8cf8f66ecbc252ac8f7f06cca68aba88508ddfde3a6a34feb1678ad1694b4f88"
)
# Helm's KEYS file (public keys) at a pinned commit, and its SHA-256.
HELM_PUBRING_URL=https://raw.githubusercontent.com/helm/helm/e74a4c6c6c2469f6dabab54879d3f53a9ed8bbf3/KEYS
HELM_PUBRING_SHA256=5de12e8dca75f8a72d1ad4e9a05a6f9de0356ee520bf0bd703bd2d37a536e85b
# Primary key fingerprint of the Helm maintainer who signed the pinned release (Scott Rigby).
HELM_SIGNER=208DD36ED5BB3745A16743A4C7C6FBB5B91C1155

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

if [[ "${HELM:-1}" != 0 ]]; then
  command -v gpg >/dev/null \
    || { echo "install-scanners: gpg is needed to verify helm's signature (HELM=0 skips helm)" >&2; exit 1; }
  hpin="$(printf '%s\n' "${HELM_PINS[@]}" | grep "^$PLATFORM|")" \
    || { echo "install-scanners: no helm pin for $PLATFORM" >&2; exit 1; }
  hsha="${hpin#*|}"
  hdir="${PLATFORM/\//-}"
  asset="helm-v$HELM_VERSION-$hdir.tar.gz"
  fetch "$tmp/helm.tar.gz" "https://get.helm.sh/$asset"
  [[ "$(sha256 "$tmp/helm.tar.gz")" == "$hsha" ]] || { echo "checksum mismatch for helm $HELM_VERSION" >&2; exit 1; }
  fetch "$tmp/helm.tar.gz.asc" "https://github.com/helm/helm/releases/download/v$HELM_VERSION/$asset.asc"
  fetch "$tmp/KEYS" "$HELM_PUBRING_URL"
  [[ "$(sha256 "$tmp/KEYS")" == "$HELM_PUBRING_SHA256" ]] || { echo "install-scanners: helm KEYS file changed (checksum mismatch)" >&2; exit 1; }
  # A keyring of its own: nothing the user trusts, and nothing left behind.
  gnupg="$tmp/gnupg"
  mkdir -m 0700 "$gnupg"
  gpg --homedir "$gnupg" --batch --quiet --no-autostart --import "$tmp/KEYS" 2>/dev/null \
    || { echo "install-scanners: cannot import helm's KEYS" >&2; exit 1; }
  # gpg must succeed and report a good signature (GOODSIG) and VALIDSIG <signing key> ...
  # <primary key> with the pinned primary key; any bad, unverifiable, expired or revoked
  # signature or key fails, and so does a good signature by any other key in KEYS. A detached
  # signature writes no signed data to stdout, and status fields are escaped.
  helm_sig() { echo "install-scanners: signature of helm $HELM_VERSION not verified for key $HELM_SIGNER: $1" >&2; exit 1; }
  status="$(gpg --homedir "$gnupg" --batch --no-autostart --status-fd 1 --verify "$tmp/helm.tar.gz.asc" "$tmp/helm.tar.gz" 2>/dev/null)" \
    || helm_sig "gpg failed"
  # Statuses about a signature, not about other keys of KEYS (which the trustdb check reports).
  if grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|REVKEYSIG|EXPKEYSIG|EXPSIG|NO_PUBKEY) ' <<<"$status"; then
    helm_sig "$(grep -oE '^\[GNUPG:\] [A-Z_]+' <<<"$status" | tr '\n' ' ')"
  fi
  grep -qE '^\[GNUPG:\] GOODSIG ' <<<"$status" || helm_sig "no good signature"
  awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $NF }' <<<"$status" | grep -qxF "$HELM_SIGNER" \
    || helm_sig "not signed by the pinned key"
  tar -xzf "$tmp/helm.tar.gz" -C "$tmp" "$hdir/helm"
  mv "$tmp/$hdir/helm" "$tmp/helm"
  if [[ -n "${LICENSES:-}" ]]; then
    mkdir -p "$tmp/licenses/helm"
    tar -xzf "$tmp/helm.tar.gz" -C "$tmp" "$hdir/LICENSE"
    mv "$tmp/$hdir/LICENSE" "$tmp/licenses/helm/LICENSE"
  fi
  verified+=("helm|$HELM_VERSION")
fi

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
