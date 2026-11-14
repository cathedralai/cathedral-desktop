#!/bin/bash
# Fetch noVNC's core and vendor directories next to the sealed stream page (not committed).
# The tarball must match the sha256 in novnc-sha256.txt (next to this script); a version with no entry is
# refused. Any earlier core/ and vendor/ are removed first and stay removed on a refusal or failure: an
# install from before the pin was never checked. The script reads no environment variable.
# Usage: bash tee/web/get-novnc.sh [version]
set -euo pipefail
V="${1:-1.6.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TABLE="$HERE/novnc-sha256.txt"

rm -rf "$HERE/core" "$HERE/vendor"
T=""
cleanup() { status=$?; [ -n "$T" ] && rm -rf "$T"; [ "$status" -ne 0 ] && rm -rf "$HERE/core" "$HERE/vendor"; return "$status"; }
trap cleanup EXIT

WANT="$(awk -v v="$V" '$1 !~ /^#/ && $1 == v { print $2 }' "$TABLE")"
if ! [[ "$WANT" =~ ^[0-9a-f]{64}$ ]]; then
  echo "get-novnc: no sha256 for noVNC ${V} in ${TABLE}; refusing to download it" >&2
  exit 1
fi

T="$(mktemp -d)"
curl -fsSL -o "$T/novnc.tgz" "https://github.com/novnc/noVNC/archive/refs/tags/v${V}.tar.gz"
if command -v sha256sum >/dev/null 2>&1; then GOT="$(sha256sum "$T/novnc.tgz" | cut -d' ' -f1)"; else GOT="$(shasum -a 256 "$T/novnc.tgz" | cut -d' ' -f1)"; fi
if [ "$GOT" != "$WANT" ]; then
  echo "get-novnc: sha256 mismatch for noVNC ${V}: wanted ${WANT}, got ${GOT}; nothing installed" >&2
  exit 1
fi

tar xzf "$T/novnc.tgz" -C "$T"
mkdir -p "$HERE/core" "$HERE/vendor"
cp -R "$T/noVNC-${V}/core/." "$HERE/core/"
cp -R "$T/noVNC-${V}/vendor/." "$HERE/vendor/"
mkdir -p "$HERE/fixtures"
cp "$HERE/../fixtures/amd-genoa-ark.der" "$HERE/../fixtures/amd-genoa-ask.der" "$HERE/fixtures/"
echo "noVNC ${V} (sha256 ${GOT}) core and vendor in $HERE; AMD certs in $HERE/fixtures"
