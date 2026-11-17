#!/bin/bash
# Rebuild the run 5 desktop TEE box inputs and check its launch fingerprint (AB#363).
#
# 1. kernel:   build Linux 7.0.14 from kernel.org with kernel-7.0.14-desktop.config (kbuild-repro.sh)
# 2. initrd:   download the base initrd-net.gz from the GitHub release, check its sha256, swap in
#              tee/rootfs/initrd-init-desktop (mkinitrd-desktop.sh)
# 3. firmware: download Ubuntu's ovmf-amdsev 2025.11-3ubuntu7.3 and take /usr/share/ovmf/OVMF.amdsev.fd
# 4. check:    tee/build/measure/check.sh with manifests/run5-example.manifest.json: every input hash
#              and the computed fingerprint must equal the manifest (and the chip-signed value of run 5)
#
# Needs: Ubuntu 26.04 x86_64 with gcc 15.2.0-16ubuntu1 and binutils 2.46 (another toolchain gives
# another kernel hash), build-essential libelf-dev libssl-dev flex bison bc cpio curl, Python 3.11+,
# about 3 GB of disk. No AMD hardware is needed.
#
# Usage: tee/build/recipes/rebuild-and-check.sh [WORKDIR]   (default: ./tee-rebuild)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
W=$(mkdir -p "${1:-tee-rebuild}" && cd "${1:-tee-rebuild}" && pwd)
RELEASE=${RELEASE:-https://github.com/cathedralai/cathedral-desktop/releases/download/tee-fingerprint-run5}
OVMF_DEB=ovmf-amdsev_2025.11-3ubuntu7.3_all.deb
OVMF_DEB_SHA256=f2a54db678d98ce1a5ac27155cb037cbf6e3efc918d11a35af1ca4606a290d29
mkdir -p "$W/inputs"

echo "== kernel"
"$HERE/kbuild-repro.sh" "$W/kbuild" "$W/inputs"

echo "== initrd"
curl -sSfL -o "$W/initrd-net.gz" "$RELEASE/initrd-net.gz"
"$HERE/mkinitrd-desktop.sh" "$W/initrd-net.gz" "$W/inputs"

echo "== firmware"
cd "$W"
[ -f "$OVMF_DEB" ] || apt-get download ovmf-amdsev=2025.11-3ubuntu7.3
echo "$OVMF_DEB_SHA256  $OVMF_DEB" | sha256sum -c
rm -rf ovmf; dpkg-deb -x "$OVMF_DEB" ovmf
cp ovmf/usr/share/ovmf/OVMF.amdsev.fd inputs/

echo "== fingerprint"
"$REPO/tee/build/measure/check.sh" "$REPO/tee/build/manifests/run5-example.manifest.json" "$W/inputs"
