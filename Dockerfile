# Cathedral sealed desktop, prebuilt: the result of desktop/bootstrap baked into a registry image, so a
# room boots with nothing to install. CI builds and pushes it (.github/workflows/publish-image.yml);
# use it with `ctdesk new --image ghcr.io/cathedralai/cathedral-desktop@sha256:...`.
#
# Explicit start:image uses this supervised CMD. The existing sealed API/ctdesk path overrides
# CMD with sleep infinity and still execs desktop-up, until its separate gated cutover.
# The public quick tunnel carries display traffic through Cloudflare; its VNC password is per room.
#
# Everything the desktop runs is installed here, at build. Starting it fetches nothing.
#
# No VNC password is baked in: desktop-up generates one per room into /work/vnc-password at start.

# debian:trixie-slim, multi-arch index digest resolved 2026-11-10.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

LABEL org.opencontainers.image.source="https://github.com/cathedralai/cathedral-desktop" \
      org.opencontainers.image.description="Cathedral sealed desktop: TigerVNC display, openbox, branded noVNC, Chromium, cloudflared"

# bootstrap reads these to fetch and check one cloudflared release instead of the latest.
ARG CLOUDFLARED_VERSION=2026.10.7
ARG CLOUDFLARED_SHA256=70b1a1e0f46033ffc8d90b406e554044ba6cbf2e4360295ef1163aed31e09393
# The default display server and the viewer, pinned to exact Debian trixie versions (2026-11-24). A
# version the mirror no longer carries fails the build; bump the pin then, on purpose.
ARG TIGERVNC_VERSION=1.15.0+dfsg-2.1~deb13u1
ARG NOVNC_VERSION=1:1.6.0-2
# KasmVNC for `desktop-up --server kasm` (opt in). amd64 trixie package, checksum taken 2026-11-22.
ARG KASMVNC_VERSION=1.5.2
ARG KASMVNC_SHA256=6ed957163275088a5ce52b525f82f145014e3289699d576ce26745a4249407f8

# Run the same bootstrap a stock room runs, so the image cannot drift from it. Then render the default
# 1280x800 wallpaper (desktop-up would render it on first start) and drop the build-only files.
COPY desktop /tmp/desktop
RUN bash /tmp/desktop/bootstrap \
 && /opt/desktop/wallpaper.sh /opt/desktop/wallpaper.png 1280x800 \
 && test ! -e /work/vnc-password \
 && find /var/lib/apt/lists /tmp -mindepth 1 -delete

CMD ["desktop-up", "--tunnel", "--foreground"]
