#!/bin/bash
# Rebuild the desktop TEE box initrd byte for byte (AB#363).
#
# Output: OUT/initrd-desktop.gz, expected sha256
#   44108c44c956b8f519fdb8bfb5ab9a8e2eac4303e7a73e48cdb2b43504b5c349
#
# initrd-desktop.gz = the base initrd-net.gz with /init replaced by tee/rootfs/initrd-init-desktop.
# The base has no recipe yet. It is published as a release asset (initrd-net.gz, sha256 below) so the
# step from base to measured initrd can be checked. See tee/build/README.md for what the base holds.
#
# The initrd is measured (kernel-hashes=on), so the same inputs must give the same bytes: fixed file
# times, sorted entries, cpio --reproducible, gzip -n (no name and no time in the header).
#
# Usage: tee/build/recipes/mkinitrd-desktop.sh BASE_INITRD_NET_GZ [OUT]   (default OUT: ./out)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
INIT="$HERE/../../rootfs/initrd-init-desktop"
BASE_SHA256=f2ec74c1acd48628b89b4e5634498a1d437b15a830fa943edd4996fb55209b76
EXPECTED=44108c44c956b8f519fdb8bfb5ab9a8e2eac4303e7a73e48cdb2b43504b5c349
BASE=$(cd "$(dirname "${1:?usage: $0 BASE_INITRD_NET_GZ [OUT]}")" && pwd)/$(basename "$1")
OUT=$(mkdir -p "${2:-out}" && cd "${2:-out}" && pwd)

echo "$BASE_SHA256  $BASE" | sha256sum -c

W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; cd "$W"
zcat "$BASE" | cpio -id --quiet
cp "$INIT" init; chmod 755 init
find . -exec touch -h -d @0 {} +
find . -print0 | LC_ALL=C sort -z | cpio -o -0 -H newc --reproducible --owner=0:0 --quiet | gzip -9 -n > "$OUT/initrd-desktop.gz"

got=$(sha256sum "$OUT/initrd-desktop.gz" | cut -d' ' -f1)
echo "$got  $OUT/initrd-desktop.gz"
if [ "$got" = "$EXPECTED" ]; then echo "INITRD MATCH"; else echo "INITRD DIFFERENT (expected $EXPECTED)"; exit 1; fi
