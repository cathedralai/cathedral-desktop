#!/usr/bin/env python3
"""CDP shim (AB#593): a local TCP listener that opens one sealed stream per connection to the box's
Chromium debugging port, so Playwright, browser-use or any CDP client connects to 127.0.0.1 and the
bytes cross the relay as ciphertext bound to the box's attestation.

    python3 cdp_shim.py --box HOST:8444 --listen 127.0.0.1:9333 --ticket-key ticket.key \
                        (--measurement HEX ... | --allow-any-measurement) [--allow-dev]
    python3 cdp_shim.py --box wss://relay.example/stream ...    # same, through a WebSocket relay
    playwright: chromium.connect_over_cdp("http://127.0.0.1:9333")

Chromium builds the webSocketDebuggerUrl from the Host header it sees, so the client keeps coming
back through the shim; no HTTP rewriting needed. Each connection is one handshake and one report
verification (the VCEK is cached on disk). A ws:// or wss:// --box opens one WebSocket per
connection instead of one TCP connection (ws_pipe.py); the relay sees ciphertext either way.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

from mint_ticket import minter
from sealed_stream import Verify, open_stream


def is_relay_url(box: str) -> bool:
    return box.startswith(("ws://", "wss://"))


async def dial(box: str):
    """A byte pipe to the box: a WebSocket relay for ws:// and wss://, plain TCP for HOST:PORT."""
    if is_relay_url(box):
        from ws_pipe import open_ws_pipe  # only relay users need the websockets package
        return await open_ws_pipe(box)
    host, port = box.rsplit(":", 1)
    return await asyncio.open_connection(host, int(port))


async def handle(local_r: asyncio.StreamReader, local_w: asyncio.StreamWriter, box: str, verify: Verify, target: str, ticket: str, mint=None,
                 open_timeout: float = 15):
    t0 = time.monotonic()
    w = None
    try:
        # One deadline for dial plus handshake: a relay that upgrades and then goes silent must not hold the
        # local connection open forever.
        async with asyncio.timeout(open_timeout):
            r, w = await dial(box)
            s = await open_stream(r, w, target=target, verify=verify, ticket=ticket, mint=mint)
    except Exception as e:  # report to stderr, close both sides
        print(f"shim: open failed: {type(e).__name__}: {e}", file=sys.stderr)
        if w is not None:
            w.close()
        local_w.close()
        return
    print(f"shim: stream open in {(time.monotonic() - t0) * 1000:.0f} ms, attestation {s.attestation}", file=sys.stderr)

    async def up():
        try:
            while True:
                data = await local_r.read(32 << 10)
                if not data:
                    break
                await s.send(data)
        finally:
            s.close()

    async def down():
        try:
            while True:
                data = await s.recv()
                local_w.write(data)
                await local_w.drain()
        except Exception:
            pass
        finally:
            local_w.close()

    await asyncio.gather(up(), down(), return_exceptions=True)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--box", required=True, help="HOST:PORT of the box's sealed stream, or a ws:// or wss:// relay URL to it")
    ap.add_argument("--listen", default="127.0.0.1:9333")
    ap.add_argument("--target", default="cdp", choices=["cdp", "vnc", "job"])
    ap.add_argument("--ticket-key", help="Ed25519 mint key: one fresh ticket per connection (what CDP needs)")
    ap.add_argument("--ticket", default="", help="one single-use ticket; good for a single connection only")
    ap.add_argument("--measurement", action="append", default=[], help="allowed MEASUREMENT (hex); repeatable")
    ap.add_argument("--product", default="Genoa")
    ap.add_argument("--allow-any-measurement", action="store_true", help="accept any build when no --measurement is given (to learn a fingerprint; tests only)")
    ap.add_argument("--allow-dev", action="store_true", help="accept a dev box with no report (tests only)")
    ap.add_argument("--open-timeout", type=float, default=15, help="seconds to reach the box and finish the handshake")
    a = ap.parse_args()
    if not is_relay_url(a.box) and ":" not in a.box:
        ap.error("--box takes HOST:PORT or a ws:// or wss:// URL")
    # Without a list the report proves a genuine chip, not our image: make the choice explicit before listening.
    if not a.measurement and not a.allow_any_measurement:
        ap.error("give --measurement HEX (repeatable) to say which build to trust, or --allow-any-measurement to accept any build")
    lh, lp = a.listen.rsplit(":", 1)
    try:
        verify = Verify(product=a.product, allowed_measurements=a.measurement,
                        allow_dev=a.allow_dev, allow_any_measurement=a.allow_any_measurement)
    except ValueError as e:
        ap.error(str(e))
    # CDP opens a connection per target and reconnects freely, and a ticket is
    # single use: one --ticket serves the first connection and nothing after it.
    mint = minter(a.ticket_key, a.target) if a.ticket_key else None
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, a.box, verify, a.target, a.ticket, mint, a.open_timeout), lh, int(lp))
    print(f"shim: {a.target} via sealed stream to {a.box}, listening on {a.listen}", file=sys.stderr)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
