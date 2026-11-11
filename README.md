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
verification. Before claiming a live proof, download the sandbox evidence and check it offline:

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

## Security notes

- The quick tunnel is a demo path. TLS ends at Cloudflare, not in the guest, and the tunnel bypasses
  Cathedral's edge and broker. The product path is AB#421 (Preview URL with TLS in the guest) and
  AB#425 (streams through the edge). Do not describe this as an attested desktop.
- noVNC is behind a VNC password (`/work/vnc-password`, generated per room, 0600). RFB listens on
  localhost only. Keep the URL out of public channels, and delete the room when the demo ends.
- The agent sees only screenshots. Keep credentials out of the room.
