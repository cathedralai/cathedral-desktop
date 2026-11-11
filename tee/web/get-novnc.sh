#!/bin/bash
# Fetch noVNC's core and vendor directories next to the sealed stream page (not committed).
# Usage: bash tee/web/get-novnc.sh [version]
set -euo pipefail
V="${1:-1.6.0}"
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$(mktemp -d)"
curl -fsSL -o "$T/novnc.tgz" "https://github.com/novnc/noVNC/archive/refs/tags/v${V}.tar.gz"
tar xzf "$T/novnc.tgz" -C "$T"
mkdir -p "$HERE/core" "$HERE/vendor"
cp -R "$T/noVNC-${V}/core/." "$HERE/core/"
cp -R "$T/noVNC-${V}/vendor/." "$HERE/vendor/"
mkdir -p "$HERE/fixtures"
cp "$HERE/../fixtures/amd-genoa-ark.der" "$HERE/../fixtures/amd-genoa-ask.der" "$HERE/fixtures/"
echo "noVNC ${V} core and vendor in $HERE; AMD certs in $HERE/fixtures"
