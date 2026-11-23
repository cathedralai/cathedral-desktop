# cathedral-desktop

A Linux desktop inside a Cathedral sealed sandbox, driven by a computer-use agent through the
public API. Every click, keystroke and screenshot is one `ctcli sandbox exec`, so Cathedral signs a
receipt for each step. Tracked as ADO AB#573 under AB#56 (mission M-D).

**Status: a spike and demo, not a Cathedral product.** On cathedral.computer the streamed desktop
(computer-use) is still marked coming soon, and no sealed desktop evidence is published. The
product path is AB#421 (preview URL with TLS in the guest) and AB#425 (streams through the edge).
Until one of those ships with published evidence, describe this as a demo you run yourself.

What it is: Xvfb + openbox + picom + tint2 in the Cathedral look (Inter, JetBrains Mono, one coral
accent), Chromium, xfce4-terminal, xdotool and scrot inside a stock sealed room (AMD SEV-SNP host,
gVisor room). x11vnc serves the display on localhost only; a branded noVNC page sits in front of it;
an optional cloudflared quick tunnel makes that page reachable from a browser. The link carries the
VNC password in the URL fragment, so one click opens the live desktop with no prompt and the password
never reaches the tunnel or the server.

What it is not: not Omarchy. Try Omarchy is a Mac app (QEMU on Apple's Hypervisor, aarch64 image)
and cannot run inside a gVisor room. Hyprland headless under gVisor is untested and a follow-up.

## Quick start

```sh
# ctcli 0.5.19+, logged in (CTCLI_CONFIG picks the login file)
./ctdesk new --size sealed-4x8 --hours 2 --tunnel   # create, bootstrap (about 60 s), start, print the one-click URL
./ctdesk shot ID                                    # screenshot to ./screen.png and open it
./ctdesk act ID -- mousemove 640 400 click 1        # one xdotool action
./ctdesk run ID -- bash -c 'export DISPLAY=:1; setsid browser https://cathedral.computer &'
./ctdesk url ID                                     # the one-click URL (password in the fragment) and the raw VNC password
./ctdesk down ID                                    # delete the room
```

Agent loop (Claude computer toolset, `claude-opus-5-5`; needs `ANTHROPIC_API_KEY`):

```sh
uv venv .venv && uv pip install --python .venv/bin/python anthropic
.venv/bin/python agent/cathedral_computer_use.py --sandbox ID \
  --max-turns 5 \
  --task "Open a terminal and run uname -a"
```

Screenshots and `receipts.json` land in `runs/<timestamp>/`. The log records exec request IDs, not
signed receipt IDs; `complete: true` means the agent ended normally, not that the receipts passed
verification. Before you call a live run verified, download the sandbox evidence and check it offline:

```sh
ctcli sandbox evidence ID -o bundle.json
ctcli receipt verify --bundle bundle.json
```

Keep the bundle with the run log, record the verifier verdict, then delete the test sandbox.

## Prebuilt image

`ctdesk new` spends most of its time in `desktop/bootstrap` (about 117 s of 150 s). The prebuilt image is
that bootstrap run at build time, so a room starts with nothing to install.

- Publish: run the `publish-image` workflow by hand (Actions, workflow_dispatch). It pushes
  `ghcr.io/cathedralai/cathedral-desktop:<git sha>` for linux/amd64 and prints the digest in the job summary.
- Make it public: the sealed pool pulls public images only. GHCR creates the package private; changing its
  visibility is a manual step in the package settings, and the workflow never does it.
- Use: name the image by digest, never by tag.

```sh
./ctdesk new --image ghcr.io/cathedralai/cathedral-desktop@sha256:<digest> --tunnel   # or CTDESK_IMAGE=...
./ctdesk new --image ghcr.io/cathedralai/cathedral-desktop@sha256:<digest> --dry-run  # print the create, send nothing
```

With `--image`, ctdesk skips the upload and bootstrap and execs `desktop-up` straight away; without it,
nothing changes. ctcli's `--image` takes catalog names only, so ctdesk posts this create to
`/v1/sandboxes` itself with the ctcli login's key (`$CTCLI_CONFIG`; the key is never printed). Both paths
print seconds for the create and until the desktop is ready. The VNC password is still generated per room
at start; the image has none.

The next image built from this source declares `desktop-up --tunnel --foreground` as its CMD
(AB#709). A local `docker run` therefore starts the desktop and a Cloudflare quick tunnel. Display
traffic passes through Cloudflare; the per-room VNC password remains required. Foreground startup
waits for the X display, a responding local web page and a VNC protocol greeting, and requires a
fresh tunnel link before reporting ready. This is local readiness, not a check of public tunnel
reachability. If a desktop process exits, startup fails, or the container is stopped, the supervisor
clears the link files and terminates its process groups. It does not print the password-bearing URL.

This source change does not enable image startup in the sealed service. Publication must produce a
new immutable digest; the measured hotel allowlist must pair that digest with the exact CMD above.
The API must opt eligible rooms into `start: "image"`, pass `DESKTOP_ROOM` for their room identity,
and read readiness without starting a second desktop. Until that coordinated cutover, the existing
API and ctdesk create path overrides CMD with `sleep infinity` and keeps its exec-based startup.
Do not change the production image pin before the digest, eligible fleet and API startup mode agree.

Run `python3 desktop/test_startup.py` for isolated readiness, child-exit and signal tests. They do not
start a real desktop or establish a live sealed-room proof. CI builds an unpublished image and runs
`bash desktop/test-image.sh cathedral-desktop-ci` in disposable containers with networking disabled:
local readiness, service failure, missing tunnel and the legacy exec path. The published digest and
the gated service still need their live acceptance run.

## Rebuild and check the fingerprint

The desktop TEE box (`tee/`) is an AMD SEV-SNP guest. Its launch fingerprint is the MEASUREMENT the
AMD chip signs into each attestation report. It covers the firmware, the kernel, the initrd and the
kernel command line (which carries the dm-verity root hash of the read-only rootfs), and the vCPU count.

Published fingerprint, run 5 (7 Nov 2026), 2 vCPUs, EPYC-v4, policy 0x30000, `sev-snp-measure` 0.0.13:

```
106b6e56b5c5a03bbb759962112ca0c181fb01798dd8f9812a9794974e2f326689ce12732b4af4c0cc8ecc2b1fc2ff6d
```

That value is the MEASUREMENT in the chip-signed report from run 5 on real SEV-SNP hardware. Every
input is pinned in `tee/build/manifests/run5-example.manifest.json`.

Rebuild it yourself (Ubuntu 26.04 x86_64 with gcc 15.2.0-16ubuntu1, binutils 2.46 and zstd 1.5.7; about
3 minutes on 48 cores, 3 GB of disk, no AMD hardware):

```sh
sudo apt-get install -y build-essential libelf-dev libssl-dev flex bison bc gawk zstd cpio curl python3-venv
git clone https://github.com/cathedralai/cathedral-desktop && cd cathedral-desktop
tee/build/recipes/rebuild-and-check.sh
```

It builds Linux 7.0.14 from kernel.org with the pinned config (`62a3737a...`), rebuilds the initrd
(`44108c44...`), takes `OVMF.amdsev.fd` from Ubuntu's `ovmf-amdsev` 2025.11-3ubuntu7.3 (`ac27e626...`),
computes the fingerprint and prints `RESULT: PASS` only if all four equal the manifest. To check a live
box, compare the MEASUREMENT in its attestation report with the value above; `tee/web/snp-verify.js`
verifies the report's AMD signature chain.

What this does and does not show (details in `tee/build/README.md`):
- It shows the number follows from these inputs: the kernel rebuilds byte for byte from kernel.org
  source, and the initrd repacks byte for byte from a copied base. Another gcc, binutils or zstd
  version gives another kernel hash.
- The base initrd (`initrd-net.gz`, release asset `tee-fingerprint-run5`) and the firmware are copied
  files without a build recipe here. The base carries a `boxd` binary of unknown source that the init
  never runs (see "Finding" in `tee/build/README.md`). The rootfs build is not pinned yet.
- Receipts and reports are rooted in the AMD chip, not in a Cathedral key. A matching fingerprint says
  which code booted; it is not by itself a claim that no operator can see inside the box. The open
  items for that claim are tracked separately.

## Layout

| Path | Role |
|---|---|
| `desktop/bootstrap` | apt install of the desktop stack inside a stock room, idempotent, about 60 s |
| `desktop/desktop-up` | starts Xvfb, openbox, picom, tint2, x11vnc, the branded page, optional tunnel; `--restart` reloads the look |
| `desktop/theme/` | openbox theme, tint2 panel, picom, terminal colours, GTK dark, wallpaper renderer, launcher entries |
| `desktop/web/index.html` | the branded noVNC page: status chip, room id, password from the URL fragment |
| `desktop/shot` | screenshot to `/work/screen.png`; `--b64` prints it for one-call capture |
| `desktop/browser` | Chromium with the flags that work as root under gVisor |
| `ctdesk` | the CLI above, customer path only (`ctcli sandbox exec/download`) |
| `agent/cathedral_computer_use.py` | computer-use loop; one receipted exec per action |
| `Dockerfile` | the prebuilt image: runs `desktop/bootstrap` at build, base image and cloudflared pinned |
| `.github/workflows/publish-image.yml` | builds and pushes the image to GHCR, by hand only |
| `evidence/` | screenshots from live rooms |
| `tee/` | the SEV-SNP desktop TEE box: boxd, rootfs, clients, verifiers, fingerprint tools and rebuild recipes |

## Sealed pool facts this relies on (6 Nov 2026)

- Custom images are closed on the sealed pool today: `image-build` rejects ENV and COPY, and both a
  FROM+RUN-only `image-build` and `image-import` of a registry reference return
  `sandbox_capacity_unavailable` (`sealed_only`). So the desktop installs itself at runtime instead.
  The prebuilt image takes a different path: a create that names a public registry digest in `image`.
- `ctcli sandbox process start` is `unsupported_on_sealed_pool`, but background children of an
  exec survive the exec. `desktop-up` starts everything with `setsid` and returns.
- `--network internet` gives real egress (Debian mirrors, GitHub, Cloudflare). The customer default
  is `deny_all`.
- Receipts are public JSON: `GET https://cathedral.computer/v1/receipts/<room_receipt_id>`, one per
  create, exec and file read, chained by `prev_sha256` and signed by Cathedral.

## The TEE box (tee/)

`tee/` holds a desktop that runs inside an AMD SEV-SNP confidential machine, and the code that checks it.
What is true today, and what is not yet, is in [tee/PROMISE.md](tee/PROMISE.md).

- The TEE box runs inside an AMD SEV-SNP confidential machine. The chip encrypts its memory.
- Before the client sends its ticket or anything you type, it checks the box's attestation report: the AMD
  certificate chain, the report's signature, the build fingerprint against the list the client is given, and
  that the machine does not allow debugging or migration. A link can waive the build list; the page then
  shows ANY BUILD ACCEPTED. The Python client's test flags waive these checks.
- If a check fails, the page stops and says which one.
- The client encrypts to a key that only the checked box holds. Relays and the network carry encrypted
  frames. They see sizes, timing and the box's report: chip id, build fingerprint, firmware level.
- The box has no disk it can write to. Its work lives in encrypted memory and is gone when it stops.
- Today Cathedral holds the key that opens a box, so Cathedral can see its screen.
- Whoever serves the viewer page can see the screen it shows. Today the relay that carries the stream also
  serves the page.
- The host can stop the box, cut the stream, see the names the box looks up and the sites it connects to,
  and read anything it sends unencrypted.
- Reports are vouched for by the AMD chip.

## Security notes

- The quick tunnel is a demo path. TLS ends at Cloudflare, not in the guest, and the tunnel bypasses
  Cathedral's edge and broker. The product path is AB#421 (Preview URL with TLS in the guest) and
  AB#425 (streams through the edge). Do not describe this as an attested desktop.
- noVNC is behind a VNC password (`/work/vnc-password`, generated per room, 0600). RFB listens on
  localhost only. Keep the URL out of public channels, and delete the room when the demo ends.
- The agent sees only screenshots. Keep credentials out of the room.
