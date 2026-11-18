#!/usr/bin/env bash
# Check a manifest against real files.
#   1. the installed sev-snp-measure is the version the manifest pins
#   2. every input file's sha256 equals the manifest's
#   3. the computed fingerprint equals the manifest's, for every vCPU count it lists
# Usage: check.sh MANIFEST INPUTS_DIR     Exit 0 only when everything matches.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=venv.sh
. "$here/venv.sh"
[ $# -eq 2 ] || { echo "usage: $0 MANIFEST INPUTS_DIR" >&2; exit 2; }
exec "$MEASURE_PY" -I "$here/manifest.py" check "$1" "$2" --tool "$MEASURE_TOOL"
