#!/bin/bash
# Build the TEE box desktop rootfs (AB#592): Debian trixie amd64 with the cathedral-desktop stack and
# boxd, as a read-only squashfs plus a dm-verity hash tree. The root hash goes on the kernel command
# line (dm-mod.create=), so kernel-hashes=on measures the whole rootfs through the command line.
#
# Run as root on amd64 Debian 13 with internet (a sealed room works):
#   bash tee/rootfs/build-desktop-rootfs.sh /work/rootfs-out
# Outputs in OUT: desktop.squashfs, desktop.verity, desktop.roothash, desktop.dm-create,
#                 desktop.manifest, desktop.sha256
set -euo pipefail
OUT="${1:-/work/rootfs-out}"
WORK="${WORK:-/work/rootfs-build}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TOP="$(cd "$HERE/../.." && pwd)"
SALT="${VERITY_SALT:-636174686564726c2d6465736b746f702d76657269747920202020202020202020}"
export DEBIAN_FRONTEND=noninteractive
t0=$(date +%s)
log() { echo "[$(( $(date +%s) - t0 ))s] $*"; }

log "host tools"
APT="apt-get -qq -o DPkg::Lock::Timeout=300"
$APT update
$APT install -y --no-install-recommends mmdebstrap squashfs-tools cryptsetup-bin golang-go ca-certificates curl >/dev/null

log "boxd from source"
mkdir -p "$WORK"
( cd "$TOP/tee/boxd" && CGO_ENABLED=0 go build -ldflags='-s -w' -o "$WORK/boxd" . )

PKGS="bash coreutils util-linux busybox-static udhcpc iproute2 ca-certificates curl procps psmisc dbus-x11 \
xvfb x11-xserver-utils x11-utils x11-apps xdotool scrot imagemagick \
x11vnc openbox tint2 feh picom xfce4-terminal \
chromium fonts-dejavu fonts-noto-color-emoji fonts-inter fonts-jetbrains-mono \
papirus-icon-theme adwaita-icon-theme gnome-themes-extra python3"
R="$WORK/root"
if [ ! -d "$R/usr" ]; then
  log "mmdebstrap trixie"
  mmdebstrap --variant=minbase --mode=root --include="$(echo $PKGS | tr ' ' ',')" \
    --aptopt='Acquire::Retries "3"' --dpkgopt='path-exclude=/usr/share/doc/*' --dpkgopt='path-exclude=/usr/share/man/*' \
    --dpkgopt='path-exclude=/usr/share/locale/*' --dpkgopt='path-include=/usr/share/locale/locale.alias' \
    trixie "$R" http://deb.debian.org/debian
fi

log "cathedral-desktop files"
install -m 755 "$WORK/boxd" "$R/usr/local/bin/boxd"
install -m 755 "$TOP/desktop/desktop-up" "$TOP/desktop/shot" "$TOP/desktop/browser" "$R/usr/local/bin/"
mkdir -p "$R/opt/desktop/web" "$R/usr/share/themes/Cathedral/openbox-3" "$R/etc/boxd"
install -m 644 "$TOP/desktop/theme/openbox-themerc" "$R/usr/share/themes/Cathedral/openbox-3/themerc"
install -m 644 "$TOP/desktop/theme/tint2rc" "$TOP/desktop/theme/picom.conf" "$TOP/desktop/theme/terminalrc" "$TOP/desktop/theme/gtk-settings.ini" "$R/opt/desktop/"
install -m 755 "$TOP/desktop/theme/apply-openbox.py" "$TOP/desktop/theme/wallpaper.sh" "$R/opt/desktop/"
install -m 644 "$TOP/desktop/theme/cathedral-terminal.desktop" "$TOP/desktop/theme/cathedral-browser.desktop" "$R/usr/share/applications/"
install -m 755 "$HERE/box-init" "$R/sbin/box-init"
install -m 755 "$HERE/box-dhcp" "$R/sbin/box-dhcp"
install -m 644 "$TOP/tee/fixtures/amd-genoa-ark.der" "$R/etc/boxd/ark.der"
install -m 644 "$TOP/tee/fixtures/amd-genoa-ask.der" "$R/etc/boxd/ask.der"
# Ticket public key (tee/client/mint_ticket.py keygen); without it the box must run with -noticket.
TICKET_PUB="${TICKET_PUB:-$TOP/tee/fixtures/ticket.pub}"
if [ -s "$TICKET_PUB" ]; then
  install -m 644 "$TICKET_PUB" "$R/etc/boxd/ticket.pub"
  log "ticket.pub installed ($(sha256sum "$TICKET_PUB" | cut -c1-16))"
else
  log "no ticket.pub: the box will run with -noticket"
fi
mkdir -p "$R/work" "$R/run" "$R/root/.config"
chroot "$R" /opt/desktop/wallpaper.sh /opt/desktop/wallpaper.png 1280x800 >/dev/null 2>&1 || log "wallpaper render skipped"
chroot "$R" fc-cache -f >/dev/null 2>&1 || true
: > "$R/etc/machine-id"
chroot "$R" dpkg-query -W | sort > "$WORK/desktop.manifest"

log "squashfs"
mkdir -p "$OUT"
mksquashfs "$R" "$OUT/desktop.squashfs" -comp zstd -Xcompression-level 15 -noappend -no-xattrs -all-root -mkfs-time 0 -all-time 0 -quiet
BLOCKS=$(( ($(stat -c %s "$OUT/desktop.squashfs") + 4095) / 4096 ))

log "dm-verity ($BLOCKS data blocks)"
veritysetup format --no-superblock --salt="$SALT" --data-block-size=4096 --hash-block-size=4096 \
  --root-hash-file="$OUT/desktop.roothash" "$OUT/desktop.squashfs" "$OUT/desktop.verity" >/dev/null
ROOT="$(cat "$OUT/desktop.roothash")"
veritysetup verify --no-superblock --salt="$SALT" --data-block-size=4096 --hash-block-size=4096 \
  --data-blocks="$BLOCKS" "$OUT/desktop.squashfs" "$OUT/desktop.verity" "$ROOT"
# dm-mod.create= value: one line, identical for every box, so the measurement stays one number.
echo "desktop,,,ro,0 $(( BLOCKS * 8 )) verity 1 /dev/vda /dev/vdb 4096 4096 $BLOCKS 0 sha256 $ROOT $SALT" > "$OUT/desktop.dm-create"
cp "$WORK/desktop.manifest" "$OUT/desktop.manifest"
( cd "$OUT" && sha256sum desktop.squashfs desktop.verity desktop.roothash desktop.dm-create desktop.manifest > desktop.sha256 )
log "done: $(du -h "$OUT/desktop.squashfs" | cut -f1) squashfs, $(du -h "$OUT/desktop.verity" | cut -f1) verity, root hash ${ROOT:0:16}…"
cat "$OUT/desktop.sha256"
