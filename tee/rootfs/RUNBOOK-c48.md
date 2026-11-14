# Runbook: the desktop TEE box on c48 (AB#364 with AB#591 to AB#593)

For Mr Spock, after 18:00Z on 6 Nov. Nothing here touches the miner box, the broker or the hotels.
One box at a time; c48 memory is the limit.

## Inputs

- Kernel: `/root/snptest/kbuild.sh` output with `SQUASHFS`, `DM_VERITY`, `DM_INIT`, `OVERLAY_FS`,
  `VIRTIO_BLK` built in (plus what AB#362 already has).
- Initrd: `initrd-net.gz` with `init` replaced by `tee/rootfs/initrd-init-desktop` (same busybox,
  same `tsm_report.ko` and `sev-guest.ko`), rebuilt the way `kit/retime/mkinitrd.sh` does it.
- Rootfs: `INBOX/blueprint2-tee-20261104/rootfs/desktop.squashfs`, `desktop.verity`,
  `desktop.dm-create` (checksums in `desktop.sha256`). Copy to `/root/snptest/`.
- boxd is inside the rootfs (`/usr/local/bin/boxd`, built from `tee/boxd` during the rootfs build).
- Host side: `tee/client/` (Python 3.11+, `pip install cryptography playwright websockify`) and
  `tee/web/` with `bash tee/web/get-novnc.sh` run once.

## Boot one box

On top of the AB#362 QEMU line (2 vCPU, 4 GiB, tap, kernel-hashes=on), add:

```
-drive file=/root/snptest/desktop.squashfs,if=virtio,format=raw,readonly=on
-drive file=/root/snptest/desktop.verity,if=virtio,format=raw,readonly=on
-append "console=ttyS0 rdinit=/init panic=-1 quiet loglevel=0 dm-mod.create=\"$(cat /root/snptest/desktop.dm-create)\""
```

Per-box networking by DHCP on the tap (dnsmasq), nothing per box on the command line. The console
prints `ROOTFS ok`, `NET <ip>`, `KEY`, `CERT`, `STREAMKEY`, `BINDING`, `ATTEST ok`, `LISTEN :8443 :8444`,
`DESKTOP ready <uptime>`. Record that uptime: it is the boot-to-desktop number for AB#364.

## Capture the fixture and check the link (host)

```
python3 tee/client/capture_fixture.py --box BOXIP:8443 --out ~/Documents/INBOX/blueprint2-tee-20261104/fixtures
```

Writes report.bin, cert.der, vcek.der, prints the MEASUREMENT (the AB#363 fingerprint), and opens a
sealed stream to target `job` with the full verifier on. Then on the Mac: `node tee/web/test-snp-verify.mjs`
runs the real-report checks.

## See the desktop (host relay, browser on the Mac)

```
websockify --web tee/web 6090 BOXIP:8444          # relay: carries ciphertext only
# browser (over an SSH tunnel to the host, or the host's address):
http://HOST:6090/index.html?relay=ws://HOST:6090/websockify&target=vnc&fp=<MEASUREMENT>&certs=<url serving vcek.der>
```

The page verifies the report in the browser, shows `attested · <measurement> · chip <id>`, and
renders the desktop over the stream. Without `fp=` the page refuses. To learn a build's fingerprint, add `nofp=1`; the chip then says `ANY BUILD ACCEPTED`.
Screenshot that chip and the desktop for AB#592.

## Drive it (CDP, host or Mac through a tunnel)

```
python3 tee/client/cdp_shim.py --box BOXIP:8444 --listen 127.0.0.1:9333 --measurement <MEASUREMENT>
python3 -c "from playwright.sync_api import sync_playwright as p
with p() as pw: b=pw.chromium.connect_over_cdp('http://127.0.0.1:9333'); pg=b.contexts[0].new_page(); pg.goto('https://cathedral.computer'); print(pg.title())"
```

Record connect and action latency for AB#593. `HALT` on the console powers the box off.

## What to post

AB#363: the MEASUREMENT and what the command line contains. AB#364: boot-to-desktop time, the
console lines, one box at 2 vCPU / 4 GiB. AB#592: the chip screenshot and the desktop screenshot.
AB#593: the Playwright title and timings. Then Toby.

## Tickets (from image 3 onward)

The image carries `/etc/boxd/ticket.pub`, so boxd no longer runs `-noticket`: every stream needs a
single-use ticket. A ticket names the box it is for by the box's stream key, so `--box` is the box
itself and the mint reads the key off it (it is in ATTEST, before any ticket is asked for):

```sh
K=~/Documents/TOOLS/.credentials/cathedral-tee-ticket-20261106.key
T=$(python3 tee/client/mint_ticket.py issue --key $K --box BOXIP:8444 --target vnc)
```

One ticket, one stream: the box refuses a repeat (`TICKET replay refused`), a ticket minted for
another box (`TICKET for another box refused`), and any expiry more than 10 minutes out. Anything
that opens more than one stream mints per connection rather than carrying a ticket:

- `capture_fixture.py --ticket-key $K` mints its own.
- `cdp_shim.py --ticket-key $K` mints one per connection, which is what CDP needs: Chromium opens a
  connection per target and reconnects freely, so a single `--ticket` serves the first and nothing
  after it.
- viewer: add `#ticket=$T` to the URL (after the `?...` part, as a fragment: the page removes it from the address bar; a link with a `ticket=` in the query is refused, and the page says the ticket must follow the `#`. Treat a ticket that was put in a query as used and mint a new one) (`--target vnc`). The page cannot mint (the mint key stays off
  the browser), so one ticket is one view: a reload needs a fresh `T`. AB#591's mint API is what
  removes that step.

## VNC authentication

The TEE box runs x11vnc with no password (`desktop-up --vnc-auth none`, set by `box-init`): it
listens on localhost inside the box and the sealed stream, attested and ticketed, is the gate. The
viewer still handles a box that asks for one, and the public-tunnel path keeps its password.
