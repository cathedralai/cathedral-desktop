# Desktop rootfs for the TEE box (AB#592)

One measured image: `desktop.squashfs` (read-only root) + `desktop.verity` (hash tree) + a root hash
that rides on the kernel command line, identical for every box, so `kernel-hashes=on` covers the
whole rootfs and the AB#363 fingerprint stays one number.

## Build

```sh
bash tee/rootfs/build-desktop-rootfs.sh /work/rootfs-out      # root, amd64 Debian 13, internet
```

Builds boxd from `tee/boxd`, runs mmdebstrap (trixie, minbase + the desktop packages), installs the
cathedral-desktop files, renders the wallpaper, makes the squashfs (zstd), formats dm-verity with a
fixed salt and no superblock, verifies it, and writes `desktop.dm-create`.

## Boot (for the kit on c48)

Initrd: `tee/rootfs/initrd-init-desktop` replaces `kit/rootfs-net/init` (same busybox initrd, same
modules). It mounts `/dev/dm-0`, overlays a tmpfs, and `switch_root`s into `/sbin/box-init`.

QEMU, on top of the AB#362 command:

```
-drive file=desktop.squashfs,if=virtio,format=raw,readonly=on
-drive file=desktop.verity,if=virtio,format=raw,readonly=on
-append "console=ttyS0 rdinit=/init panic=-1 quiet loglevel=0 dm-mod.create=\"$(cat desktop.dm-create)\""
```

The network comes from DHCP on the tap (dnsmasq on the host), never from the command line.

Kernel options the guest needs built in: `SQUASHFS`, `DM_VERITY`, `DM_INIT`, `OVERLAY_FS`, `VIRTIO_BLK`.

## Inside the box

`box-init` brings up eth0 by DHCP, starts `boxd` (8443 TLS line protocol, 8444 sealed stream),
`desktop-up` (Xvfb 1280x800, openbox, picom, tint2, x11vnc on localhost), and Chromium with
`--remote-debugging-port=9222` on localhost. Console lines: `NET`, `KEY`, `CERT`, `STREAMKEY`,
`BINDING`, `ATTEST`, `LISTEN`, `DESKTOP ready`. `HALT` on the console powers off.

AMD ARK and ASK (Genoa) ship in `/etc/boxd`; the VCEK for the chip is fetched by the client from KDS.
