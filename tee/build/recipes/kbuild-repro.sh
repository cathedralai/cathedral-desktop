#!/bin/bash
# Rebuild the desktop TEE box kernel byte for byte (AB#363).
#
# Output: OUT/bzImage-desktop-7.0.14-repro, expected sha256
#   62a3737a50236cdbdebd3884e16d33fa02b8c6be03c09ab257d4cd15098f3f54
#
# Inputs: upstream Linux 7.0.14 from cdn.kernel.org (sha256 pinned below, equal to kernel.org's sha256sums.asc) and
# kernel-7.0.14-desktop.config in this folder. The config is Ubuntu's 7.0 config with SEV_GUEST,
# TSM_REPORTS, squashfs (zstd), dm-verity with dm-mod.create, overlayfs and virtio built in.
#
# Toolchain used for the published hash: Ubuntu 26.04, gcc 15.2.0-16ubuntu1, binutils 2.46-3ubuntu2 and
# zstd 1.5.7+dfsg-3 (the kernel is compressed with zstd -22), with libelf-dev, libssl-dev, flex, bison,
# bc and gawk installed. Another compiler, linker or zstd version gives another hash.
#
# Why the build stamps are fixed: the kernel embeds build time, user, host and a build counter.
# Why MODULE_SIG_KEY is empty: with the default key path the build makes a fresh random signing key and
# embeds its certificate, so no two builds match. This guest builds no modules and MODULE_SIG_FORCE is
# off, so nothing is lost.
#
# Usage: tee/build/recipes/kbuild-repro.sh [WORKDIR] [OUT]   (defaults: ./kbuild and ./out)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
V=7.0.14
EXPECTED=62a3737a50236cdbdebd3884e16d33fa02b8c6be03c09ab257d4cd15098f3f54
# Pinned here so a tampered tarball never reaches make; it equals kernel.org's sha256sums.asc entry.
TARBALL_SHA256=de9999b784d2293f00d39c62d8f92a08ab8a54bc4e80ffd250a0c09cb07a0f98
W=$(mkdir -p "${1:-kbuild}" && cd "${1:-kbuild}" && pwd)
OUT=$(mkdir -p "${2:-out}" && cd "${2:-out}" && pwd)
JOBS=${JOBS:-$(nproc)}

cd "$W"
echo "$TARBALL_SHA256  linux-$V.tar.xz" | sha256sum -c --status 2>/dev/null || {
  rm -f linux-$V.tar.xz; curl -sSfLO https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-$V.tar.xz; }
echo "$TARBALL_SHA256  linux-$V.tar.xz" | sha256sum -c

export KBUILD_BUILD_TIMESTAMP="Thu Nov  6 00:00:00 UTC 2026" KBUILD_BUILD_USER=cathedral \
  KBUILD_BUILD_HOST=cathedral KBUILD_BUILD_VERSION=1 SOURCE_DATE_EPOCH=1793923200

rm -rf repro; mkdir repro; tar xf linux-$V.tar.xz -C repro --strip-components=1; cd repro
cp "$HERE/kernel-$V-desktop.config" .config
scripts/config --set-str MODULE_SIG_KEY "" -d MODULE_SIG_ALL
make olddefconfig >/dev/null
grep -qx 'CONFIG_MODULE_SIG_KEY=""' .config || { echo 'MODULE_SIG_KEY not empty'; exit 1; }
nice -n 19 make -j"$JOBS" bzImage >/dev/null
[ ! -e certs/signing_key.pem ] && [ ! -s certs/signing_key.x509 ] || { echo 'signing key still generated'; exit 1; }
cp arch/x86/boot/bzImage "$OUT/bzImage-desktop-$V-repro"

got=$(sha256sum "$OUT/bzImage-desktop-$V-repro" | cut -d' ' -f1)
echo "$got  $OUT/bzImage-desktop-$V-repro"
if [ "$got" = "$EXPECTED" ]; then echo "KERNEL MATCH"; else echo "KERNEL DIFFERENT (expected $EXPECTED)"; exit 1; fi
