# Desktop rootfs for the TEE box (AB#592)

One measured image: `desktop.squashfs` (read-only root) + `desktop.verity` (hash tree) + a root hash
that rides on the kernel command line, identical for every box, so `kernel-hashes=on` covers the
whole rootfs and the AB#363 fingerprint stays one number.

## Build

```sh
bash tee/rootfs/build-desktop-rootfs.sh /work/rootfs-out      # root, amd64 Linux, internet
```

Builds boxd from `tee/boxd`, runs mmdebstrap (trixie, minbase + the desktop packages), installs the
cathedral-desktop files, renders the wallpaper, makes the squashfs (zstd), formats dm-verity with a
fixed salt and no superblock, verifies it, and writes `desktop.dm-create`.

## Reproducible

Same inputs = same `desktop.squashfs` and root hash. That is what lets anyone recompute the AB#363
measurement instead of trusting ours. The inputs are the source tree, `SNAPSHOT`, `TICKET_PUB` (the
32-byte Ed25519 ticket public key; default `tee/fixtures/ticket.pub`) and `VERITY_SALT`. All four
are written into `desktop.manifest`, so a published manifest says exactly what to pass.

Shown so far: one host (c48, Ubuntu, AMD EPYC), five builds over four days, 32 and 4 CPUs, all
byte-identical. A build on a second host (another distro, filesystem and CPU vendor) is still open.

- Every package comes from one snapshot.debian.org timestamp (`SNAPSHOT`, default in the script),
  and `SOURCE_DATE_EPOCH` is that timestamp.
- The build tools come from the same snapshot: the script bootstraps mmdebstrap (two debs pinned
  by sha256), makes a trixie builder chroot, and runs the image build inside it, in private mount and
  UTS namespaces. The host only needs perl, apt (with gpgv), dpkg-deb, curl, ca-certificates,
  unshare, chroot, mount, sha256sum and GNU date, on amd64. The host's own mksquashfs or Go never
  touch the image.
- boxd builds with `-trimpath -buildvcs=false -buildid=` and `GOTOOLCHAIN=local`.
- Before mksquashfs the script normalises what a build leaves behind: `/etc/hostname`
  (`sealed-box`), `/etc/resolv.conf`, machine-id, logs (truncated), apt lists and caches, ldconfig
  aux-cache, `__pycache__`, the wallpaper's PNG date chunks. Every mtime goes to 0 before `fc-cache`,
  matching what the squashfs stores, so the font caches are identical and still valid at boot.
  `/dev` ships empty: its contents depend on whether the build host can mknod, and the initrd moves
  devtmpfs over it at boot.
- The build fails without a 32-byte ticket key, so it can never produce a box that runs `-noticket`.
- `desktop.manifest` starts with the source commit, the snapshot, `SOURCE_DATE_EPOCH`, the builder
  tool versions, the boxd sha256, the ticket.pub sha256 and the verity salt, then every package and
  version in the image. `desktop.files` lists the sha256 of every file in the image.

To check a published root hash: check out the commit in the manifest, run the script with a fresh
`WORK` and the manifest's `TICKET_PUB` and salt, and compare `desktop.roothash`. If it differs,
`diff` the two `desktop.files` to find the file that moved. A new `SNAPSHOT` (for package updates)
gives a new hash on purpose.

Known limit: apt still checks signing-key expiry against the verifier's clock. Once the Debian
archive keys of this snapshot expire, the build stops with EXPKEYSIG instead of producing a
different image. Move `SNAPSHOT` forward (a new hash) before then.

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
