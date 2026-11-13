#!/usr/bin/env bash
# Positive control: recompute the fingerprints of runs 4 to 7 on the c48 box from their saved
# inputs and compare each with what the notes recorded. A tool or flag mistake shows up here,
# before anyone trusts a fingerprint computed for a new build.
#
# CATHEDRAL_CONTROL_DIR must point at a folder laid out like the blueprint2-tee notes:
#   c48-boot-artifacts-20261110/   OVMF.amdsev.fd bzImage-desktop-7.0.14 bzImage-desktop-7.0.14-repro initrd-desktop.gz
#   rootfs/desktop.dm-create       image 4 verity line (run 4)
#   fixtures-run4/report.bin       chip report of run 4
#   c48-run5-repro-20261107/       cmdline.txt measurement.expected report.bin
#   c48-run6-rootfs-repro-20261111/ and c48-run7-rootfs-bc5054a-20261111/   measure.append measure.expected
# Command line files (cmdline.txt, measure.append, desktop.dm-create) may end with exactly one newline,
# which is not part of the command line; any other trailing newline is an error.
# Unset: skip with exit 0. Any mismatch or missing file: exit 1.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${CATHEDRAL_CONTROL_DIR:-}" ]; then
  echo "SKIP: CATHEDRAL_CONTROL_DIR is not set; the control inputs (about 40 MB) are not in this repository."
  exit 0
fi
# shellcheck source=venv.sh
. "$here/venv.sh"
d="$CATHEDRAL_CONTROL_DIR"
boot="$d/c48-boot-artifacts-20261110"
run5="$d/c48-run5-repro-20261107"
run6="$d/c48-run6-rootfs-repro-20261111"
run7="$d/c48-run7-rootfs-bc5054a-20261111"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
py() { "$MEASURE_PY" -I "$here/manifest.py" "$@"; }
version="$("$MEASURE_TOOL" --version | awk '{print $NF}')"
fail=0
summary=()

# $1 label, $2 kernel file, $3 flag (--cmdline-file or --dm-create-file), $4 that file,
# $5 expected fingerprint (96 hex), $6 source of the expected value.
# The command line is read from the file by manifest.py, never through the shell, so no byte is
# stripped silently: one trailing newline is the file's line ending, any other trailing newline is an error.
control() {
  local label="$1" kernel="$2" flag="$3" cfile="$4" expected="$5" source="$6" m="$work/$1.json"
  if [ ! -f "$kernel" ] || [ ! -f "$cfile" ] || [ -z "$expected" ]; then
    echo "FAIL $label: missing input (kernel $kernel)"; summary+=("$label MISSING"); fail=1; return
  fi
  py make --firmware "$boot/OVMF.amdsev.fd" --kernel "$kernel" --initrd "$boot/initrd-desktop.gz" \
     "$flag" "$cfile" --vcpu-type EPYC-v4 --vcpus 2 --expected "$expected" --version "$version" \
     --out "$m" --note "$label" || { summary+=("$label MANIFEST-ERROR"); fail=1; return; }
  echo "== $label (expected value from $source)"
  if py check "$m" "$boot" --tool "$MEASURE_TOOL"; then
    summary+=("$label recorded ${expected:0:8}..${expected: -8} computed same MATCH")
  else
    summary+=("$label recorded ${expected:0:8}..${expected: -8} MISMATCH"); fail=1
  fi
}

# All inputs sit in the boot-artifacts folder, which is what the manifests' inputs folder is.
rep4="$(py report-measurement "$d/fixtures-run4/report.bin" 2>/dev/null)"
control run4 "$boot/bzImage-desktop-7.0.14" --dm-create-file "$d/rootfs/desktop.dm-create" "$rep4" "fixtures-run4/report.bin offset 0x90 (chip-signed)"
control run5 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run5/cmdline.txt" \
  "$(tr -d '\n' < "$run5/measurement.expected" 2>/dev/null)" "run5 measurement.expected"
control run6 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run6/measure.append" \
  "$(tr -d '\n' < "$run6/measure.expected" 2>/dev/null)" "run6 measure.expected (computed on c48, no chip report)"
control run7 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run7/measure.append" \
  "$(tr -d '\n' < "$run7/measure.expected" 2>/dev/null)" "run7 measure.expected (computed on c48, no chip report)"

echo "== run5 chip report"
chip="$(py report-measurement "$run5/report.bin" 2>/dev/null)"
rec5="$(tr -d '\n' < "$run5/measurement.expected" 2>/dev/null)"
if [ -n "$chip" ] && [ "$chip" = "$rec5" ]; then
  echo "ok   run5 report.bin MEASUREMENT ${chip:0:8}..${chip: -8} equals measurement.expected"
  summary+=("run5-report MEASUREMENT ${chip:0:8}..${chip: -8} equals recorded MATCH")
else
  echo "FAIL run5 report.bin MEASUREMENT '${chip:0:8}' vs measurement.expected '${rec5:0:8}'"
  summary+=("run5-report MISMATCH"); fail=1
fi
# run 4 recorded value is the report itself; the notes' README also names its first 12 hex characters
if [ "${rep4:0:12}" != "2882ec3b4132" ]; then
  echo "FAIL run4 report.bin prefix ${rep4:0:12} differs from the 2882ec3b4132 named in the boot-artifacts README"
  summary+=("run4-prefix MISMATCH"); fail=1
fi

echo
echo "SUMMARY (sev-snp-measure $version)"
printf '  %s\n' "${summary[@]}"
if [ "$fail" -eq 0 ]; then echo "CONTROL: PASS"; else echo "CONTROL: FAIL"; fi
exit "$fail"
