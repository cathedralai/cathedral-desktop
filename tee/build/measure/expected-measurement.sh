#!/usr/bin/env bash
# Print the launch fingerprint for each vCPU count in a manifest.
# Usage: expected-measurement.sh MANIFEST INPUTS_DIR [VCPUS]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=venv.sh
. "$here/venv.sh"
[ $# -ge 2 ] || { echo "usage: $0 MANIFEST INPUTS_DIR [VCPUS]" >&2; exit 2; }
extra=()
[ -n "${3:-}" ] && extra=(--vcpus "$3")
exec "$MEASURE_PY" -I "$here/manifest.py" fingerprint "$1" "$2" --tool "$MEASURE_TOOL" ${extra[@]+"${extra[@]}"}
