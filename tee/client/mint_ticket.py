#!/usr/bin/env python3
"""Ticket mint for the private spike (stands in for the Cathedral API until AB#591's mint lands).

    python3 mint_ticket.py keygen --out ticket.key            # writes ticket.key (private) and ticket.pub (raw 32 bytes)
    python3 mint_ticket.py issue --key ticket.key --room BOX --target vnc [--ttl 120]

The box pins ticket.pub at /etc/boxd/ticket.pub (install it into the rootfs with TICKET_PUB=path on the
build). A ticket is base64url(JSON {"room","target","exp"}) "." base64url(Ed25519 signature), single
use, at most 10 minutes ahead (boxd refuses longer). Keep ticket.key on the host that mints only.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen")
    g.add_argument("--out", default="ticket.key")
    i = sub.add_parser("issue")
    i.add_argument("--key", default="ticket.key")
    i.add_argument("--room", required=True)
    i.add_argument("--target", required=True, choices=["vnc", "cdp", "job"])
    i.add_argument("--ttl", type=int, default=120, help="seconds, at most 600")
    a = ap.parse_args()
    if a.cmd == "keygen":
        k = Ed25519PrivateKey.generate()
        fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        open(a.out.rsplit(".", 1)[0] + ".pub", "wb").write(pub)
        print(f"wrote {a.out} (private, 0600) and {a.out.rsplit('.', 1)[0]}.pub (raw 32 bytes, goes into the rootfs at /etc/boxd/ticket.pub)")
        return
    k = Ed25519PrivateKey.from_private_bytes(open(a.key, "rb").read())
    body = json.dumps({"room": a.room, "target": a.target, "exp": int(time.time()) + min(a.ttl, 600)}, separators=(",", ":"), sort_keys=True).encode()
    sys.stdout.write(f"{b64u(body)}.{b64u(k.sign(body))}\n")


if __name__ == "__main__":
    main()
