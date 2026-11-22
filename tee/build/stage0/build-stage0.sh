#!/usr/bin/env bash
# Build the enforcing Oak stage0 (sev_kernel_hashes on) and wrap it into an SEV-SNP IGVM file (AB#433).
#
# 1. Oak at OAK_COMMIT, with oak-sev_kernel_hashes.patch: crate_features = ["sev_kernel_hashes"] in
#    stage0/BUILD and stage0_sev/BUILD. With it, stage0 checks the kernel, initrd and command line it
#    loads over fw_cfg against the measured SEV hash table and halts on a mismatch.
# 2. bazel build //stage0_bin:stage0_bin
# 3. buildigvm at BUILDIGVM_COMMIT: --cpucount 1 sev-snp
# 4. sha256 of both outputs against the values the SNP test host booted. A mismatch is reported, not
#    hidden; the fingerprint must then be recomputed with ../measure/igvm_measurement.py.
#
# Needs: git, bazelisk (Oak's .bazelversion picks Bazel; 8.5.1 was used), cargo, about 25 GB of disk
# for the Bazel cache. No AMD hardware is needed to build.
#
# Usage: tee/build/stage0/build-stage0.sh [WORKDIR]   (default: ./stage0-build)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(mkdir -p "${1:-stage0-build}" && cd "${1:-stage0-build}" && pwd)
OAK_COMMIT=f07cdb50315cbb3dff7dd4b0e6b9505f425bf42e
BUILDIGVM_COMMIT=58264592c62ca8828de4874870de0fd2e8ae3dbf
STAGE0_BIN_SHA256=350034b47d06f92f4a693e7b11a36f876375e69a1048e2dfd26d2f58351a2b4d
STAGE0_IGVM_SHA256=6f2606fb7efd8a8ce3776ea31bb0d194af621d8d87f2e0f810aa3a039e84997e
BAZEL=${BAZEL:-bazelisk}

echo "== oak $OAK_COMMIT"
[ -d "$W/oak/.git" ] || git clone -q --filter=blob:none https://github.com/project-oak/oak "$W/oak"
git -C "$W/oak" checkout -q "$OAK_COMMIT"
git -C "$W/oak" checkout -q -- stage0/BUILD stage0_sev/BUILD
git -C "$W/oak" apply "$HERE/oak-sev_kernel_hashes.patch"
grep -q '^    crate_features = \["sev_kernel_hashes"\],' "$W/oak/stage0/BUILD"
grep -q '^    crate_features = \["sev_kernel_hashes"\],' "$W/oak/stage0_sev/BUILD"

echo "== stage0_bin"
(cd "$W/oak" && "$BAZEL" build //stage0_bin:stage0_bin)
cp -f "$W/oak/bazel-bin/stage0_bin/stage0_bin" "$W/stage0_bin-kernelhashes"

echo "== buildigvm $BUILDIGVM_COMMIT"
[ -d "$W/buildigvm/.git" ] || git clone -q https://gitlab.com/qemu-project/buildigvm.git "$W/buildigvm"
git -C "$W/buildigvm" checkout -q "$BUILDIGVM_COMMIT"
(cd "$W/buildigvm" && cargo build --release --locked -q)
"$W/buildigvm/target/release/buildigvm" --firmware "$W/stage0_bin-kernelhashes" \
  --output "$W/stage0-kernelhashes.igvm" --cpucount 1 sev-snp

echo "== hashes"
fail=0
check() {
  local got; got=$(sha256sum "$2" | cut -d' ' -f1)
  if [ "$got" = "$1" ]; then echo "ok   $(basename "$2") $got"
  else echo "DIFF $(basename "$2") $got, the SNP test host booted $1"; fail=1; fi
}
check "$STAGE0_BIN_SHA256" "$W/stage0_bin-kernelhashes"
check "$STAGE0_IGVM_SHA256" "$W/stage0-kernelhashes.igvm"
echo "IGVM: $W/stage0-kernelhashes.igvm"
exit "$fail"
