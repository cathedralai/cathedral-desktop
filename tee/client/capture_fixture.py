#!/usr/bin/env python3
"""Capture a real box's attestation as test fixtures and check it (run on the host next to the box).

    python3 capture_fixture.py --box 127.0.0.1:20000 --out INBOX/blueprint2-tee-20261104/fixtures

Talks the AB#361 line protocol on the box's 8443 (TLS 1.3, cert not verified here: the report binds
it), writes report.bin, cert.der and the VCEK from AMD KDS as vcek.der, then opens the sealed stream
on 8444 to fetch the binding and run the full verifier. Prints the measurement for AB#363.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import socket
import ssl
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sealed_stream import Verify, open_stream  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--box", required=True, help="HOST:PORT of the box's 8443 (hostfwd on the harness)")
    ap.add_argument("--stream", help="HOST:PORT of the box's 8444 (default: same host, port+1)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--product", default="Genoa")
    a = ap.parse_args()
    host, port = a.box.rsplit(":", 1)
    port = int(port)
    os.makedirs(a.out, exist_ok=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode, ctx.minimum_version = False, ssl.CERT_NONE, ssl.TLSVersion.TLSv1_3
    with socket.create_connection((host, port), 10) as raw, ctx.wrap_socket(raw) as s:
        cert = s.getpeercert(binary_form=True)
        s.sendall(b"REPORT\n")
        line = b""
        while not line.endswith(b"\n"):
            line += s.recv(65536)
    parts = line.split()
    if len(parts) != 2 or parts[0] != b"REPORT":
        sys.exit(f"box answered {line[:60]!r}")
    report = bytes.fromhex(parts[1].decode())
    open(os.path.join(a.out, "report.bin"), "wb").write(report)
    open(os.path.join(a.out, "cert.der"), "wb").write(cert)
    tcb, chip = report[0x180:0x188], report[0x1A0:0x1E0].hex()
    url = f"https://kdsintf.amd.com/vcek/v1/{a.product}/{chip}?blSPL={tcb[0]}&teeSPL={tcb[1]}&snpSPL={tcb[6]}&ucodeSPL={tcb[7]}"
    with urllib.request.urlopen(url, timeout=30) as r:
        vcek = r.read()
    open(os.path.join(a.out, "vcek.der"), "wb").write(vcek)
    print(f"report {len(report)} bytes v{int.from_bytes(report[:4], 'little')}, chip {chip[:16]}…, measurement {report[0x90:0xC0].hex()}")
    print(f"cert sha256 {hashlib.sha256(cert).hexdigest()[:16]}…, vcek {len(vcek)} bytes from KDS")

    sh, sp = (a.stream.rsplit(":", 1) if a.stream else (host, str(port + 1)))

    async def check():
        r, w = await asyncio.open_connection(sh, int(sp))
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        spki = x509.load_der_x509_certificate(cert).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        s = await open_stream(r, w, target="job", verify=Verify(product=a.product, vcek_der=vcek, tls_spki=spki))
        await s.send(b"JOB 1\n")
        reply = await s.recv()
        print(f"sealed stream: attestation {s.attestation}, job reply {reply!r}")
        s.close()

    asyncio.run(check())
    print(f"fixtures in {a.out}: report.bin cert.der vcek.der")


if __name__ == "__main__":
    main()
