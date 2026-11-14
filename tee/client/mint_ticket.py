#!/usr/bin/env python3
"""Ticket mint for the private spike (stands in for the Cathedral API until AB#591's mint lands).

    python3 mint_ticket.py keygen --out ticket.key            # ticket.key (private) and ticket.pub (raw 32 bytes)
    python3 mint_ticket.py issue --key ticket.key --box HOST:8444 --target vnc [--ttl 120]

The box pins ticket.pub at /etc/boxd/ticket.pub (install it into the rootfs with TICKET_PUB=path on
the build). A ticket is base64url(JSON {"box","exp","nonce","target"}) "." base64url(Ed25519
signature), single use, at most 10 minutes ahead (boxd refuses longer). Keep ticket.key on the host
that mints only.

``box`` is the box's Noise static key, base64 as the attestation binding spells it, so a ticket opens
the one box it was minted for. The box hands that key to every client in ATTEST before it asks for a
ticket, so ``--box HOST:PORT`` reads it off the box itself; pass the base64 key directly instead when
there is nothing to connect to. ``nonce`` keeps two tickets minted in the same second distinct, which
is what lets a client open several streams at once (CDP does).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

TTL_MAX = 600


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def load_key(path: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(open(path, "rb").read())


def issue(key: Ed25519PrivateKey, *, box_static: bytes, target: str, ttl: int = 120) -> str:
    """One single-use ticket for one box, one target.

    ``box_static`` is the box's raw 32-byte Noise static key (ATTEST's ``static``
    field decoded), named in the ticket the way the binding names it.
    """
    body = json.dumps({"box": base64.b64encode(box_static).decode(),
                       "exp": int(time.time()) + min(ttl, TTL_MAX),
                       "nonce": b64u(os.urandom(16)),
                       "target": target},
                      separators=(",", ":"), sort_keys=True).encode()
    return f"{b64u(body)}.{b64u(key.sign(body))}"


def minter(key_path: str, target: str, ttl: int = 120):
    """A ``mint`` for ``open_stream``: one fresh ticket per connection, bound to that box."""
    key = load_key(key_path)
    return lambda box_static: issue(key, box_static=box_static, target=target, ttl=ttl)


async def box_static_key(host: str, port: int) -> bytes:
    """Read a box's Noise static key from its ATTEST, which precedes any ticket."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from sealed_stream import b64u_decode, read_frame, write_frame

    r, w = await asyncio.open_connection(host, port)
    try:
        write_frame(w, json.dumps({"v": 1}).encode())
        await w.drain()
        att = json.loads(await read_frame(r))
        if "error" in att:
            raise SystemExit(f"box: {att['error']}")
        return b64u_decode(att["static"])
    finally:
        w.close()


def resolve_box(value: str) -> bytes:
    """``HOST:PORT`` reads the key off the box; anything else is the base64 key itself."""
    host, _, port = value.rpartition(":")
    if host and port.isdigit():
        return asyncio.run(box_static_key(host, int(port)))
    key = base64.b64decode(value + "=" * (-len(value) % 4), validate=False)
    if len(key) != 32:
        raise SystemExit(f"--box is neither HOST:PORT nor a 32-byte base64 key ({len(key)} bytes)")
    return key


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen")
    g.add_argument("--out", default="ticket.key")
    i = sub.add_parser("issue")
    i.add_argument("--key", default="ticket.key")
    i.add_argument("--box", required=True, help="HOST:PORT of the box's sealed stream (8444), or its base64 static key")
    i.add_argument("--target", required=True, choices=["vnc", "cdp", "job", "run"])
    i.add_argument("--ttl", type=int, default=120, help=f"seconds, at most {TTL_MAX}")
    a = ap.parse_args()
    if a.cmd == "keygen":
        k = Ed25519PrivateKey.generate()
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption()))
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        open(a.out.rsplit(".", 1)[0] + ".pub", "wb").write(pub)
        print(f"wrote {a.out} (private, 0600) and {a.out.rsplit('.', 1)[0]}.pub "
              "(raw 32 bytes, goes into the rootfs at /etc/boxd/ticket.pub)")
        return
    sys.stdout.write(issue(load_key(a.key), box_static=resolve_box(a.box), target=a.target, ttl=a.ttl) + "\n")


if __name__ == "__main__":
    main()
