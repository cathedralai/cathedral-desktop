# cathedral-desktop

A Linux desktop inside a Cathedral sealed sandbox, driven by a computer-use agent through the
public API. Every click, keystroke and screenshot is one `ctcli sandbox exec`, so Cathedral signs a
receipt for each step. Tracked as ADO AB#573 under AB#56 (mission M-D).

What it is: Xvfb + openbox + tint2, Chromium, xterm, xdotool and scrot inside a stock sealed room
(AMD SEV-SNP host, gVisor room). x11vnc serves the display on localhost only; noVNC sits in front
of it; an optional cloudflared quick tunnel makes noVNC reachable from a browser.

What it is not: not Omarchy. Try Omarchy is a Mac app (QEMU on Apple's Hypervisor, aarch64 image)
and cannot run inside a gVisor room. Hyprland headless under gVisor is untested and a follow-up.

## Quick start

```sh
# ctcli 0.5.19+, logged in (CTCLI_CONFIG picks the login file)
./ctdesk new --size sealed-4x8 --hours 2 --tunnel   # create, bootstrap (about 60 s), start, print URL + password
./ctdesk shot ID                                    # screenshot to ./screen.png and open it
./ctdesk act ID -- mousemove 640 400 click 1        # one xdotool action
./ctdesk run ID -- bash -c 'export DISPLAY=:1; setsid browser https://cathedral.computer &'
./ctdesk url ID                                     # public noVNC URL and the VNC password
./ctdesk down ID                                    # delete the room
```

Agent loop (Claude computer toolset, `claude-opus-5-5`; needs `ANTHROPIC_API_KEY`):

```sh
uv venv .venv && uv pip install --python .venv/bin/python anthropic
.venv/bin/python agent/cathedral_computer_use.py --sandbox ID \
  --launch "browser https://cathedral.computer" \
  --task "Open the Pricing page and read me the price of a sealed 2x4 sandbox"
```

Screenshots and the receipt log of a run land in `runs/<timestamp>/`.

## Layout

| Path | Role |
|---|---|
| `desktop/bootstrap` | apt install of the desktop stack inside a stock room, idempotent, about 60 s |
| `desktop/desktop-up` | starts Xvfb, openbox, tint2, x11vnc, noVNC, optional tunnel; daemons outlive the exec |
| `desktop/shot` | screenshot to `/work/screen.png`; `--b64` prints it for one-call capture |
| `desktop/browser` | Chromium with the flags that work as root under gVisor |
| `ctdesk` | the CLI above, customer path only (`ctcli sandbox exec/download`) |
| `agent/cathedral_computer_use.py` | computer-use loop; one receipted exec per action |
| `Dockerfile`, `build-context.sh` | the same stack as an image, kept for the day image-import opens on the sealed pool |
| `evidence/` | screenshots from live rooms |

## Sealed pool facts this relies on (6 Nov 2026)

- Custom images are closed on the sealed pool today: `image-build` rejects ENV and COPY, and both a
  FROM+RUN-only `image-build` and `image-import` of a registry reference return
  `sandbox_capacity_unavailable` (`sealed_only`). So the desktop installs itself at runtime instead.
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
