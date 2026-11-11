#!/bin/bash
# Build the TEE box desktop rootfs (AB#592): Debian trixie amd64 with the cathedral-desktop stack and
# boxd, as a read-only squashfs plus a dm-verity hash tree. The root hash goes on the kernel command
# line (dm-mod.create=), so kernel-hashes=on measures the whole rootfs through the command line.
#
# Reproducible (AB#363): every input comes from one snapshot.debian.org timestamp, the image packages
# and the build tools too (mmdebstrap, mksquashfs, veritysetup, Go). The tools run in a builder chroot
# made from that snapshot, so the host only has to bootstrap it. Same source tree + same SNAPSHOT =
# same desktop.squashfs and root hash, on any amd64 Linux host.
#
# Run as root on amd64 Linux, internet:
#   bash tee/rootfs/build-desktop-rootfs.sh /work/rootfs-out
# Host needs: perl, apt (with gpgv), dpkg-deb, curl, ca-certificates, unshare, chroot, mount,
# sha256sum, GNU date. WORK (default /work/rootfs-build) must be absent or empty: nothing is reused.
# Inputs that change the image or hash, all written into desktop.manifest: the source tree, SNAPSHOT,
# TICKET_PUB (32-byte Ed25519 public key; default tee/fixtures/ticket.pub), VERITY_SALT.
# Outputs in OUT: desktop.squashfs, desktop.verity, desktop.roothash, desktop.dm-create,
#                 desktop.manifest, desktop.files (sha256 of every file in the image), desktop.sha256
set -euo pipefail
umask 022
export LC_ALL=C TZ=UTC DEBIAN_FRONTEND=noninteractive
SNAPSHOT="${SNAPSHOT:-20261106T203421Z}"
MIRROR="https://snapshot.debian.org/archive/debian/$SNAPSHOT"
SOURCE_DATE_EPOCH="$(date -u -d "${SNAPSHOT:0:8} ${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}" +%s)"
export SOURCE_DATE_EPOCH
SALT="${VERITY_SALT:-636174686564726c2d6465736b746f702d76657269747920202020202020202020}"
t0=$(date +%s)
log() { echo "[$(( $(date +%s) - t0 ))s] $*"; }

if [ "${1:-}" != --inside ]; then
  # Stage 1 (host): bootstrap mmdebstrap, make the builder chroot, run stage 2 inside it.
  OUT="$(mkdir -p "${1:-/work/rootfs-out}" && cd "${1:-/work/rootfs-out}" && pwd)"
  WORK="${WORK:-/work/rootfs-build}"
  TOP="$(cd "$(dirname "$0")/../.." && pwd)"
  [ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
  [ "$(dpkg --print-architecture)" = amd64 ] || { echo "amd64 host only: the image is amd64" >&2; exit 1; }
  if [ -n "${TICKET_PUB:-}" ] && [ "$(stat -c %s "$TICKET_PUB" 2>/dev/null || echo 0)" != 32 ]; then
    echo "TICKET_PUB=$TICKET_PUB is not a 32-byte Ed25519 public key" >&2; exit 1
  fi
  # Recorded in the manifest only (the image never sees it), so a mismatch can be traced to a tree.
  # An exported tree has no .git: pass SRC_REV=<commit> then.
  if [ -z "${SRC_REV:-}" ]; then
    SRC_REV="$(git -C "$TOP" rev-parse HEAD 2>/dev/null || echo unknown)"
    [ -z "$(git -C "$TOP" status --porcelain 2>/dev/null)" ] || SRC_REV="$SRC_REV-dirty"
  fi
  if [ -d "$WORK" ] && [ -n "$(ls -A "$WORK")" ]; then echo "WORK=$WORK is not empty; use a fresh one" >&2; exit 1; fi
  mkdir -p "$WORK/bootstrap/x"
  # A default ACL on WORK would override umask 022 for every directory the build makes, and the
  # resulting mode bits land in the squashfs.
  if command -v getfacl >/dev/null && [ -n "$(getfacl -d -c "$WORK" 2>/dev/null)" ]; then
    echo "WORK=$WORK carries a default ACL; use a directory without one" >&2; exit 1
  fi
  # Only these two debs come from outside the builder; pinned by hash, from a fixed snapshot.
  BOOT=https://snapshot.debian.org/archive/debian/20261106T203421Z/pool/main
  fetch() {
    curl -sSfL --retry 3 -o "$WORK/bootstrap/$2" "$BOOT/$1"
    echo "$3  $WORK/bootstrap/$2" | sha256sum -c --quiet
    dpkg-deb -x "$WORK/bootstrap/$2" "$WORK/bootstrap/x"
  }
  log "bootstrap mmdebstrap"
  fetch m/mmdebstrap/mmdebstrap_1.5.7-1+deb13u1_all.deb mmdebstrap.deb df731ee92b0ad40f9618b8b1c98c2e90635224f6b21c0905dab65ca099c8fe14
  fetch d/debian-archive-keyring/debian-archive-keyring_2025.1_all.deb keyring.deb 9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac
  B="$WORK/builder"
  log "builder chroot from $SNAPSHOT"
  # Its own mount namespace: mmdebstrap --mode=root runs `mount --make-rprivate /` in the namespace
  # it is started in, which on the host would turn off mount propagation for the whole machine. Here
  # it only touches this namespace, and a killed mmdebstrap leaves no mounts under WORK.
  unshare --mount --propagation private -- perl "$WORK/bootstrap/x/usr/bin/mmdebstrap" --quiet --variant=minbase --mode=root \
    --keyring="$WORK/bootstrap/x/usr/share/keyrings/debian-archive-keyring.gpg" \
    --include=mmdebstrap,squashfs-tools,cryptsetup-bin,golang-go,ca-certificates,mount \
    --aptopt='Acquire::Retries "3"' --aptopt='Acquire::Check-Valid-Until "false"' \
    trixie "$B" "$MIRROR"
  mkdir -p "$B/src" "$B/out"
  TP=""
  if [ -n "${TICKET_PUB:-}" ]; then install -m 644 "$TICKET_PUB" "$B/ticket.pub"; TP=/ticket.pub; fi
  # Private mount and UTS namespaces: the bind mounts vanish with the build, and no package script
  # can see the host's hostname.
  unshare --mount --uts --propagation private -- /bin/bash -euc '
    hostname sealed-box
    mount --rbind /dev "$1/dev"; mount -t proc proc "$1/proc"; mount -t sysfs sys "$1/sys"
    mount --bind "$2" "$1/src"; mount -o remount,bind,ro "$1/src"; mount --bind "$3" "$1/out"
    exec chroot "$1" /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root \
      SNAPSHOT="$4" TICKET_PUB="$5" VERITY_SALT="$6" SRC_REV="$7" /bin/bash /src/tee/rootfs/build-desktop-rootfs.sh --inside /out
  ' _ "$B" "$TOP" "$OUT" "$SNAPSHOT" "$TP" "$SALT" "$SRC_REV"
  exit 0
fi

# Stage 2 (builder chroot): the image itself. Paths here are fixed, so the host's paths never leak in.
OUT="$2"
WORK=/work
TOP=/src
R="$WORK/root"
mkdir -p "$WORK"

log "boxd from source ($(go version | cut -d' ' -f3))"
( cd "$TOP/tee/boxd" && CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOCACHE=$WORK/gocache GOPATH=$WORK/gopath \
    go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o "$WORK/boxd" . )

PKGS="bash coreutils util-linux busybox-static udhcpc iproute2 ca-certificates curl procps psmisc dbus-x11 \
xvfb x11-xserver-utils x11-utils x11-apps xdotool scrot imagemagick \
x11vnc openbox tint2 feh picom xfce4-terminal \
chromium fonts-dejavu fonts-noto-color-emoji fonts-inter fonts-jetbrains-mono \
papirus-icon-theme adwaita-icon-theme gnome-themes-extra python3"
log "mmdebstrap trixie from $SNAPSHOT"
mmdebstrap --quiet --variant=minbase --mode=root --include="$(echo $PKGS | tr ' ' ',')" \
  --aptopt='Acquire::Retries "3"' --aptopt='Acquire::Check-Valid-Until "false"' \
  --dpkgopt='path-exclude=/usr/share/doc/*' --dpkgopt='path-exclude=/usr/share/man/*' \
  --dpkgopt='path-exclude=/usr/share/locale/*' --dpkgopt='path-include=/usr/share/locale/locale.alias' \
  trixie "$R" "$MIRROR"

log "cathedral-desktop files"
install -m 755 "$WORK/boxd" "$R/usr/local/bin/boxd"
install -m 755 "$TOP/desktop/desktop-up" "$TOP/desktop/shot" "$TOP/desktop/browser" "$R/usr/local/bin/"
mkdir -p "$R/opt/desktop/web" "$R/usr/share/themes/Cathedral/openbox-3" "$R/etc/boxd"
install -m 644 "$TOP/desktop/theme/openbox-themerc" "$R/usr/share/themes/Cathedral/openbox-3/themerc"
install -m 644 "$TOP/desktop/theme/tint2rc" "$TOP/desktop/theme/picom.conf" "$TOP/desktop/theme/terminalrc" "$TOP/desktop/theme/gtk-settings.ini" "$R/opt/desktop/"
install -m 755 "$TOP/desktop/theme/apply-openbox.py" "$TOP/desktop/theme/wallpaper.sh" "$R/opt/desktop/"
install -m 644 "$TOP/desktop/theme/cathedral-terminal.desktop" "$TOP/desktop/theme/cathedral-browser.desktop" "$R/usr/share/applications/"
install -m 755 "$TOP/tee/rootfs/box-init" "$R/sbin/box-init"
install -m 755 "$TOP/tee/rootfs/box-dhcp" "$R/sbin/box-dhcp"
install -m 644 "$TOP/tee/fixtures/amd-genoa-ark.der" "$R/etc/boxd/ark.der"
install -m 644 "$TOP/tee/fixtures/amd-genoa-ask.der" "$R/etc/boxd/ask.der"
# Ticket public key (tee/client/mint_ticket.py keygen). Required: without it box-init would start boxd
# with -noticket, an image whose stream needs no ticket, so a missing key fails the build instead.
TICKET_PUB="${TICKET_PUB:-$TOP/tee/fixtures/ticket.pub}"
[ "$(stat -c %s "$TICKET_PUB" 2>/dev/null || echo 0)" = 32 ] || { echo "no 32-byte ticket.pub at $TICKET_PUB" >&2; exit 1; }
install -m 644 "$TICKET_PUB" "$R/etc/boxd/ticket.pub"
log "ticket.pub installed ($(sha256sum "$TICKET_PUB" | cut -c1-16))"
mkdir -p "$R/work" "$R/run" "$R/root/.config"
# One thread: the render must not depend on the builder's core count.
chroot "$R" env MAGICK_THREAD_LIMIT=1 OMP_NUM_THREADS=1 /opt/desktop/wallpaper.sh /opt/desktop/wallpaper.png 1280x800 >/dev/null

log "normalise build-time state"
{ [ -d "$R/usr" ] && [ "$R" != / ]; } || { echo "bad root $R" >&2; exit 1; }
# mmdebstrap copies these two from whatever ran the build (image 4 carried the sealed room's
# container hostname). box-init sets the hostname; DHCP rewrites resolv.conf when it hands out DNS.
echo sealed-box > "$R/etc/hostname"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$R/etc/resolv.conf"
: > "$R/etc/machine-id"
[ -L "$R/var/lib/dbus/machine-id" ] || rm -f "$R/var/lib/dbus/machine-id"
rm -rf "$R/root/.cache" "$R/var/cache/ldconfig/aux-cache"
find "$R/var/lib/apt/lists" "$R/var/cache/apt" -mindepth 1 -not -type d -delete
# .pyc carry source mtimes and marshal order; Python rebuilds them on the tmpfs overlay if it wants them.
find "$R" -xdev -depth -type d -name __pycache__ -exec rm -rf {} +
# fontconfig caches record each font directory's mtime and are thrown away when it does not match.
# The squashfs stores every mtime as 0, so set the tree to 0 first: the caches are then the same on
# every build and still valid at boot.
find "$R" -xdev -exec touch -h -d @0 {} +
chroot "$R" fc-cache -f >/dev/null
rm -rf "$R/root/.cache"
find "$R/var/log" -type f -exec truncate -s 0 {} +

# Plain assignments, so set -e stops the build if any of these fail (inside an echo it would not).
TOOLS="$(dpkg-query -W -f='${Package}=${Version} ' mmdebstrap squashfs-tools cryptsetup-bin golang-go)"
GOVER="$(go version | cut -d' ' -f3)"
BOXD_SHA="$(sha256sum "$WORK/boxd" | cut -d' ' -f1)"
TICKET_SHA="$(sha256sum "$R/etc/boxd/ticket.pub" | cut -d' ' -f1)"
PACKAGES="$(chroot "$R" dpkg-query -W | sort)"
[ -n "$TOOLS" ] && [ -n "$GOVER" ] && [ ${#BOXD_SHA} = 64 ] && [ ${#TICKET_SHA} = 64 ] && [ -n "$PACKAGES" ] \
  || { echo "manifest input missing" >&2; exit 1; }
printf '%s\n' "# source ${SRC_REV:-unknown}" "# snapshot $MIRROR" "# SOURCE_DATE_EPOCH $SOURCE_DATE_EPOCH" \
  "# builder $TOOLS$GOVER" "# boxd sha256 $BOXD_SHA" "# ticket.pub sha256 $TICKET_SHA" "# verity salt $SALT" \
  "$PACKAGES" > "$WORK/desktop.manifest"

# /dev last: mmdebstrap fills it with device nodes, or with empty files where the host cannot mknod,
# so it depends on the build host. The initrd moves its devtmpfs over /dev at boot, so the image needs
# only the empty directory.
find "$R/dev" -xdev -mindepth 1 -delete
# Per-file hashes, so a verifier whose root hash differs can find the file that moved.
( cd "$R" && find . -xdev -type f -print0 | sort -z | xargs -0 sha256sum ) > "$WORK/desktop.files"

log "squashfs"
# Nothing from an earlier build may survive in OUT: veritysetup does not truncate an existing hash file.
rm -f "$OUT"/desktop.squashfs "$OUT"/desktop.verity "$OUT"/desktop.roothash "$OUT"/desktop.dm-create \
  "$OUT"/desktop.manifest "$OUT"/desktop.files "$OUT"/desktop.sha256
# mksquashfs refuses SOURCE_DATE_EPOCH next to -mkfs-time/-all-time; the explicit 0 is what the tree
# was touched to above.
# -exit-on-error: a file it cannot read must fail the build, not go in as an empty file.
env -u SOURCE_DATE_EPOCH mksquashfs "$R" "$OUT/desktop.squashfs" -comp zstd -Xcompression-level 15 -noappend -no-xattrs -all-root -mkfs-time 0 -all-time 0 -exit-on-error -quiet
BLOCKS=$(( ($(stat -c %s "$OUT/desktop.squashfs") + 4095) / 4096 ))

log "dm-verity ($BLOCKS data blocks)"
veritysetup format --no-superblock --salt="$SALT" --data-block-size=4096 --hash-block-size=4096 \
  --root-hash-file="$OUT/desktop.roothash" "$OUT/desktop.squashfs" "$OUT/desktop.verity" >/dev/null
ROOT="$(cat "$OUT/desktop.roothash")"
veritysetup verify --no-superblock --salt="$SALT" --data-block-size=4096 --hash-block-size=4096 \
  --data-blocks="$BLOCKS" "$OUT/desktop.squashfs" "$OUT/desktop.verity" "$ROOT"
# dm-mod.create= value: one line, identical for every box, so the measurement stays one number.
echo "desktop,,,ro,0 $(( BLOCKS * 8 )) verity 1 /dev/vda /dev/vdb 4096 4096 $BLOCKS 0 sha256 $ROOT $SALT" > "$OUT/desktop.dm-create"
cp "$WORK/desktop.manifest" "$WORK/desktop.files" "$OUT/"
# Only the files this build wrote; a glob would also hit anything else named desktop.* in OUT.
chmod 644 "$OUT"/desktop.squashfs "$OUT"/desktop.verity "$OUT"/desktop.roothash "$OUT"/desktop.dm-create \
  "$OUT"/desktop.manifest "$OUT"/desktop.files
( cd "$OUT" && sha256sum desktop.squashfs desktop.verity desktop.roothash desktop.dm-create desktop.manifest desktop.files > desktop.sha256 )
log "done: $(du -h "$OUT/desktop.squashfs" | cut -f1) squashfs, $(du -h "$OUT/desktop.verity" | cut -f1) verity, root hash ${ROOT:0:16}..."
cat "$OUT/desktop.sha256"
