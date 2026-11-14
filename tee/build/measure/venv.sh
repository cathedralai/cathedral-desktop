#!/usr/bin/env bash
# Sourced by the other scripts. Builds a virtual environment from requirements.txt
# (every file hash-pinned; wheels only, so no source build runs an unpinned build backend) and exports MEASURE_PY and MEASURE_TOOL.
# CATHEDRAL_MEASURE_VENV chooses the folder; the default sits next to this file and is gitignored.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="${CATHEDRAL_MEASURE_VENV:-$here/.venv}"
if [ ! -x "$venv/bin/sev-snp-measure" ]; then
  echo "setting up $venv from requirements.txt (needs pypi.org once)" >&2
  "${PYTHON:-python3}" -m venv "$venv" >&2
  "$venv/bin/pip" install --quiet --only-binary :all: --require-hashes -r "$here/requirements.txt" >&2
fi
export MEASURE_PY="$venv/bin/python"
export MEASURE_TOOL="$venv/bin/sev-snp-measure"
