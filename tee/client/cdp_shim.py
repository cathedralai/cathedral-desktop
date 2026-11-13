#!/usr/bin/env python3
"""CDP shim (AB#593): a local TCP listener that opens one sealed stream per connection to the box's
Chromium debugging port, so Playwright, browser-use or any CDP client connects to 127.0.0.1 and the
bytes cross the relay as ciphertext bound to the box's attestation.

    python3 cdp_shim.py --box HOST:8444 --listen 127.0.0.1:9333 --ticket-key ticket.key \
                        (--measurement HEX ... | --allow-any-measurement) [--allow-dev]
    playwright: chromium.connect_over_cdp("http://127.0.0.1:9333")

Chromium builds the webSocketDebuggerUrl from the Host header it sees, so the client keeps coming
back through the shim; no HTTP rewriting needed. Each connection is one handshake and one report
verification (the VCEK is cached on disk).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time

from mint_ticket import minter
from sealed_stream import Verify, open_stream


async def handle(local_r: asyncio.StreamReader, local_w: asyncio.StreamWriter, box: tuple[str, int], verify: Verify, target: str, ticket: str, mint=None):
    t0 = time.monotonic()
    try:
        r, w = await asyncio.open_connection(*box)
        s = await open_stream(r, w, target=target, verify=verify, ticket=ticket, mint=mint)
    except Exception as e:  # report to stderr, close the local side
        print(f"shim: open failed: {e}", file=sys.stderr)
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
    ap.add_argument("--box", required=True, help="HOST:PORT of the box's sealed stream (or a relay to it)")
    ap.add_argument("--listen", default="127.0.0.1:9333")
    ap.add_argument("--target", default="cdp", choices=["cdp", "vnc", "job"])
    ap.add_argument("--ticket-key", help="Ed25519 mint key: one fresh ticket per connection (what CDP needs)")
    ap.add_argument("--ticket", default="", help="one single-use ticket; good for a single connection only")
    ap.add_argument("--measurement", action="append", default=[], help="allowed MEASUREMENT (hex); repeatable")
    ap.add_argument("--product", default="Genoa")
    ap.add_argument("--allow-any-measurement", action="store_true", help="accept any build when no --measurement is given (to learn a fingerprint; tests only)")
    ap.add_argument("--allow-dev", action="store_true", help="accept a dev box with no report (tests only)")
    a = ap.parse_args()
    bh, bp = a.box.rsplit(":", 1)
    lh, lp = a.listen.rsplit(":", 1)
    verify = Verify(product=a.product, allowed_measurements=a.measurement,
                    allow_dev=a.allow_dev, allow_any_measurement=a.allow_any_measurement)
    # CDP opens a connection per target and reconnects freely, and a ticket is
    # single use: one --ticket serves the first connection and nothing after it.
    mint = minter(a.ticket_key, a.target) if a.ticket_key else None
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, (bh, int(bp)), verify, a.target, a.ticket, mint), lh, int(lp))
    print(f"shim: {a.target} via sealed stream to {a.box}, listening on {a.listen}", file=sys.stderr)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
