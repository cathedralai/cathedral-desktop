#!/usr/bin/env bash
# Positive control: recompute the fingerprints of runs 4 to 7 on the c48 box from their saved inputs
# and tie each to its saved chip report. A tool or flag mistake shows up here, before anyone trusts a
# fingerprint computed for a new build.
#
# For each run:
#   1. the report's signature is verified offline by tee/web/snp-verify.js (pinned AMD Genoa root, ASK,
#      the run's VCEK, then the ECDSA signature), through verify-report.mjs; the policy must be 0x30000;
#   2. the MEASUREMENT of that verified report must equal the value the notes recorded;
#   3. sev-snp-measure on the run's saved inputs must compute that MEASUREMENT.
# REPORT_DATA binding is not checked: it is per box and not part of the measurement.
#
# CATHEDRAL_CONTROL_DIR must hold the control bundle, laid out like the blueprint2-tee notes. Every file
# the control reads is listed with its sha256 in control-inputs.sha256, and the bundle is checked against
# that list first, so a second person knows they hold the same bytes. Needs node 22 or newer.
# CATHEDRAL_CONTROL_LIST names another list; it exists only so the negative cases (a changed byte that a
# regenerated list then accepts) can be run against the same code.
# Command line files (cmdline.txt, measure.append, desktop.dm-create) may end with exactly one newline,
# which is not part of the command line; any other trailing newline is an error.
# Unset: skip with exit 0. Any mismatch or missing file: exit 1.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${CATHEDRAL_CONTROL_DIR:-}" ]; then
  echo "SKIP: CATHEDRAL_CONTROL_DIR is not set; the control bundle (about 37 MB) is not in this repository."
  exit 0
fi
# shellcheck source=venv.sh
. "$here/venv.sh"
d="$CATHEDRAL_CONTROL_DIR"
py() { "$MEASURE_PY" -I "$here/manifest.py" "$@"; }

echo "== control bundle against control-inputs.sha256"
if ! py verify-list "${CATHEDRAL_CONTROL_LIST:-$here/control-inputs.sha256}" "$d"; then
  echo "CONTROL: FAIL (the bundle in $d is not the one the list describes)"
  exit 1
fi
echo "ok   all $(wc -l < "${CATHEDRAL_CONTROL_LIST:-$here/control-inputs.sha256}" | tr -d ' ') files match"

boot="$d/c48-boot-artifacts-20261110"
run5="$d/c48-run5-repro-20261107"
run6="$d/c48-run6-rootfs-repro-20261111"
run7="$d/c48-run7-rootfs-bc5054a-20261111"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pinned="$(py pinned-version "$here/requirements.txt")" || { echo "CONTROL: FAIL (no pinned version)"; exit 1; }
fail=0
summary=()

# $1 label, $2 kernel file, $3 flag (--cmdline-file or --dm-create-file), $4 that file, $5 report dir,
# $6 file with the value the notes recorded ('' for run 4, whose notes name only a 12 character prefix),
# $7 prefix the notes name ('' when a file holds the whole value)
control() {
  local label="$1" kernel="$2" flag="$3" cfile="$4" rdir="$5" recfile="$6" recprefix="$7" m="$work/$1.json"
  echo "== $label"
  local out chip policy recorded
  if ! out="$(py verified-report "$rdir/report.bin" "$rdir/vcek.der" 2>&1)"; then
    echo "FAIL $label report: $out"; summary+=("$label report NOT VERIFIED"); fail=1; return
  fi
  read -r chip policy <<<"$out"
  if [ "$policy" != "0000000000030000" ]; then
    echo "FAIL $label report policy $policy, expected 0000000000030000"; summary+=("$label policy MISMATCH"); fail=1; return
  fi
  echo "ok   $label report signature verified (policy 0x30000), MEASUREMENT ${chip:0:8}..${chip: -8}"
  if [ -n "$recfile" ]; then
    recorded="$(tr -d '\n' < "$recfile")"
    if [ "$recorded" != "$chip" ]; then
      echo "FAIL $label notes value ${recorded:0:8} differs from the verified report ${chip:0:8}"; summary+=("$label notes-vs-report MISMATCH"); fail=1; return
    fi
    echo "ok   $label notes value equals the verified report"
  elif [ "${chip:0:12}" != "$recprefix" ]; then
    echo "FAIL $label verified report ${chip:0:12} differs from the prefix $recprefix named in the notes"; summary+=("$label notes-prefix MISMATCH"); fail=1; return
  else
    echo "ok   $label notes prefix $recprefix equals the verified report"
  fi
  py make --firmware "$boot/OVMF.amdsev.fd" --kernel "$kernel" --initrd "$boot/initrd-desktop.gz" \
     "$flag" "$cfile" --vcpu-type EPYC-v4 --vcpus 2 --expected "$chip" --version "$pinned" \
     --out "$m" --note "$label" || { summary+=("$label MANIFEST-ERROR"); fail=1; return; }
  if py check "$m" "$boot" --tool "$MEASURE_TOOL"; then
    summary+=("$label report ${chip:0:8}..${chip: -8} verified, computed same MATCH")
  else
    summary+=("$label report ${chip:0:8}..${chip: -8} computed MISMATCH"); fail=1
  fi
}

control run4 "$boot/bzImage-desktop-7.0.14" --dm-create-file "$d/rootfs/desktop.dm-create" "$d/fixtures-run4" "" 2882ec3b4132
control run5 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run5/cmdline.txt" "$run5" "$run5/measurement.expected" ""
control run6 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run6/measure.append" "$run6/fixtures" "$run6/measure.expected" ""
control run7 "$boot/bzImage-desktop-7.0.14-repro" --cmdline-file "$run7/measure.append" "$run7/fixtures" "$run7/measure.expected" ""

# Sensitivity: another guest-features or vmm-type value must change the number (or be refused), never
# fall back to a default and still match.
echo "== run5 with another launch parameter must not match"
read -r chip5 _ <<<"$(py verified-report "$run5/report.bin" "$run5/vcek.der")"
for variant in "--guest-features 0x3" "--vmm-type ec2"; do
  # shellcheck disable=SC2086
  py make --firmware "$boot/OVMF.amdsev.fd" --kernel "$boot/bzImage-desktop-7.0.14-repro" --initrd "$boot/initrd-desktop.gz" \
     --cmdline-file "$run5/cmdline.txt" --vcpu-type EPYC-v4 --vcpus 2 --expected "$chip5" --version "$pinned" \
     --out "$work/variant.json" $variant
  if py check "$work/variant.json" "$boot" --tool "$MEASURE_TOOL" >/dev/null 2>&1; then
    echo "FAIL $variant still matches the recorded measurement"; summary+=("sensitivity $variant STILL MATCHES"); fail=1
  else
    echo "ok   $variant does not match"; summary+=("sensitivity $variant differs")
  fi
done

echo
echo "SUMMARY (sev-snp-measure $pinned, pinned in requirements.txt)"
printf '  %s\n' "${summary[@]}"
if [ "$fail" -eq 0 ]; then echo "CONTROL: PASS"; else echo "CONTROL: FAIL"; fi
exit "$fail"
