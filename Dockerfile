# Cathedral sealed desktop, prebuilt: the result of desktop/bootstrap baked into a registry image, so a
# room boots with nothing to install. CI builds and pushes it (.github/workflows/publish-image.yml);
# use it with `ctdesk new --image ghcr.io/cathedralai/cathedral-desktop@sha256:...`.
#
# Run it the way the sealed pool runs rooms: the pool starts the container with its own command and
# sends every command by exec. Nothing here starts the desktop; exec `desktop-up`, as ctdesk does.
# CMD only keeps a local `docker run -d` alive for the same exec flow.
#
# No VNC password is baked in: desktop-up generates one per room into /work/vnc-password at start.

# debian:trixie-slim, multi-arch index digest resolved 2026-11-10.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

LABEL org.opencontainers.image.source="https://github.com/cathedralai/cathedral-desktop" \
      org.opencontainers.image.description="Cathedral sealed desktop: Xvfb, openbox, x11vnc, branded noVNC, Chromium, cloudflared"

# bootstrap reads these to fetch and check one cloudflared release instead of the latest.
ARG CLOUDFLARED_VERSION=2026.10.7
ARG CLOUDFLARED_SHA256=70b1a1e0f46033ffc8d90b406e554044ba6cbf2e4360295ef1163aed31e09393

# Run the same bootstrap a stock room runs, so the image cannot drift from it. Then render the default
# 1280x800 wallpaper (desktop-up would render it on first start) and drop the build-only files.
COPY desktop /tmp/desktop
RUN bash /tmp/desktop/bootstrap \
 && /opt/desktop/wallpaper.sh /opt/desktop/wallpaper.png 1280x800 \
 && test ! -e /work/vnc-password \
 && find /var/lib/apt/lists /tmp -mindepth 1 -delete

CMD ["sleep", "infinity"]
