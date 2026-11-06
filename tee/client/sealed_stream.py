"""Sealed stream client in Python (tee/SEALED-STREAM.md): Noise_NK_25519_AESGCM_SHA256 initiator over
a byte pipe, with the box's static key proven by its SEV-SNP report. Used by the CDP shim and by tests.

    import asyncio
    from sealed_stream import open_stream, Verify
    r, w = await asyncio.open_connection(host, 8444)
    s = await open_stream(r, w, target="cdp", verify=Verify(allowed_measurements=[...]))
    await s.send(b"..."); data = await s.recv()

Only the `cryptography` package is needed.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import struct
import urllib.request
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PROTOCOL = b"Noise_NK_25519_AESGCM_SHA256"
PROLOGUE = b"sealed-stream/v1"
MAX_FRAME = 1 << 20
MAX_DATA = 64 << 10
REKEY_EVERY = 1 << 20
# sha256 of the ARK certificate DER, the pin ctcli uses.
AMD_ARK_SHA256 = {
    "Genoa": "4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1",
    "Milan": "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
}
HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "fixtures")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---- SNP verification (same checks as tee/web/snp-verify.js and kit/snpverify.py)


@dataclass
class Verify:
    product: str = "Genoa"
    allowed_measurements: list[str] = field(default_factory=list)
    ark_der: bytes | None = None
    ask_der: bytes | None = None
    vcek_der: bytes | None = None
    kds_cache: str = os.path.join(HERE, ".kds-cache")
    allow_dev: bool = False
    tls_spki: bytes | None = None


def _kds(url: str, cache: str) -> bytes:
    os.makedirs(cache, exist_ok=True)
    p = os.path.join(cache, hashlib.sha256(url.encode()).hexdigest())
    if os.path.exists(p):
        return open(p, "rb").read()
    with urllib.request.urlopen(url, timeout=20) as r:
        data = r.read()
    open(p, "wb").write(data)
    return data


def verify_snp(report: bytes, static_pub: bytes, binding: str, v: Verify) -> dict:
    if len(report) < 0x2A0 + 144:
        raise ValueError("report too short")
    # binding: REPORT_DATA = sha256(canonical(binding)) || zeros, and the binding names the stream key
    bound = json.loads(binding)
    named = bound.get("sealed_stream") or {}
    if named.get("schema") != "sealed-stream/v1":
        raise ValueError("binding has no sealed_stream key")
    if base64.b64decode(named["x25519_public_b64"]) != static_pub:
        raise ValueError("binding names a different stream key than the box presented")
    if v.tls_spki is not None and bound.get("tls_spki_sha256") != hashlib.sha256(v.tls_spki).hexdigest():
        raise ValueError("binding names a different TLS key")
    if report[0x50:0x90] != hashlib.sha256(binding.encode()).digest() + bytes(32):
        raise ValueError("REPORT_DATA does not bind the presented keys")
    ark_der = v.ark_der or open(os.path.join(FIXTURES, f"amd-{v.product.lower()}-ark.der"), "rb").read()
    ask_der = v.ask_der or open(os.path.join(FIXTURES, f"amd-{v.product.lower()}-ask.der"), "rb").read()
    if hashlib.sha256(ark_der).hexdigest() != AMD_ARK_SHA256[v.product]:
        raise ValueError(f"ARK is not the pinned AMD {v.product} root")
    ark, ask = x509.load_der_x509_certificate(ark_der), x509.load_der_x509_certificate(ask_der)
    tcb, chip = report[0x180:0x188], report[0x1A0:0x1E0].hex()
    vcek_der = v.vcek_der or _kds(f"https://kdsintf.amd.com/vcek/v1/{v.product}/{chip}?blSPL={tcb[0]}&teeSPL={tcb[1]}&snpSPL={tcb[6]}&ucodeSPL={tcb[7]}", v.kds_cache)
    vcek = x509.load_der_x509_certificate(vcek_der)
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=48)
    ark.public_key().verify(ark.signature, ark.tbs_certificate_bytes, pss, hashes.SHA384())
    ark.public_key().verify(ask.signature, ask.tbs_certificate_bytes, pss, hashes.SHA384())
    ask.public_key().verify(vcek.signature, vcek.tbs_certificate_bytes, pss, hashes.SHA384())
    r = int.from_bytes(report[0x2A0:0x2A0 + 72], "little")
    s = int.from_bytes(report[0x2E8:0x2E8 + 72], "little")
    vcek.public_key().verify(encode_dss_signature(r, s), report[:0x2A0], ec.ECDSA(hashes.SHA384()))
    measurement = report[0x90:0xC0].hex()
    if v.allowed_measurements and measurement not in v.allowed_measurements:
        raise ValueError(f"MEASUREMENT {measurement[:16]} is not an allowed fingerprint")
    return {"ok": True, "test_mode": not v.allowed_measurements, "measurement": measurement, "chip_id": chip, "version": int.from_bytes(report[:4], "little")}


# ---- Noise NK


def _hkdf2(ck: bytes, ikm: bytes) -> tuple[bytes, bytes]:
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    o1 = hmac.new(temp, b"\x01", hashlib.sha256).digest()
    o2 = hmac.new(temp, o1 + b"\x02", hashlib.sha256).digest()
    return o1, o2


class CipherState:
    def __init__(self, k: bytes | None = None):
        self.k, self.n, self.frames = None, 0, 0
        if k:
            self.init(k)

    def init(self, k: bytes):
        self.k, self.aead, self.n = k, AESGCM(k), 0

    def _nonce(self, n: int) -> bytes:
        return b"\0\0\0\0" + struct.pack(">Q", n)

    def encrypt_ad(self, ad: bytes, pt: bytes) -> bytes:
        if self.k is None:
            return pt
        ct = self.aead.encrypt(self._nonce(self.n), pt, ad)
        self.n += 1
        return ct

    def decrypt_ad(self, ad: bytes, ct: bytes) -> bytes:
        if self.k is None:
            return ct
        pt = self.aead.decrypt(self._nonce(self.n), ct, ad)
        self.n += 1
        return pt

    def rekey(self):
        self.init(self.aead.encrypt(self._nonce(2**64 - 1), bytes(32), None)[:32])

    def encrypt(self, pt: bytes) -> bytes:
        if len(pt) > MAX_DATA:
            raise ValueError("frame over MAX_DATA")
        ct = self.encrypt_ad(b"", pt)
        self.frames += 1
        if self.frames % REKEY_EVERY == 0:
            self.rekey()
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        pt = self.decrypt_ad(b"", ct)
        self.frames += 1
        if self.frames % REKEY_EVERY == 0:
            self.rekey()
        return pt


class Handshake:
    def __init__(self, prologue: bytes, rs: bytes):
        self.h = PROTOCOL.ljust(32, b"\0") if len(PROTOCOL) <= 32 else hashlib.sha256(PROTOCOL).digest()
        self.ck = self.h
        self.cs = CipherState()
        self.rs = X25519PublicKey.from_public_bytes(rs)
        self.mix_hash(prologue)
        self.mix_hash(rs)

    def mix_hash(self, data: bytes):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm: bytes):
        self.ck, k = _hkdf2(self.ck, ikm)
        self.cs.init(k)

    def write_message1(self, payload: bytes) -> bytes:
        self.e = X25519PrivateKey.generate()
        eb = self.e.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.mix_hash(eb)
        self.mix_key(self.e.exchange(self.rs))
        ct = self.cs.encrypt_ad(self.h, payload)
        self.mix_hash(ct)
        return eb + ct

    def read_message2(self, msg: bytes) -> bytes:
        re = X25519PublicKey.from_public_bytes(msg[:32])
        self.mix_hash(msg[:32])
        self.mix_key(self.e.exchange(re))
        pt = self.cs.decrypt_ad(self.h, msg[32:])
        self.mix_hash(msg[32:])
        return pt

    def split(self) -> tuple[CipherState, CipherState]:
        k1, k2 = _hkdf2(self.ck, b"")
        return CipherState(k1), CipherState(k2)


# ---- framing over asyncio streams


async def read_frame(r: asyncio.StreamReader) -> bytes:
    (n,) = struct.unpack(">I", await r.readexactly(4))
    if n > MAX_FRAME:
        raise ValueError("frame too large")
    return await r.readexactly(n)


def write_frame(w: asyncio.StreamWriter, b: bytes):
    w.write(struct.pack(">I", len(b)) + b)


class Stream:
    def __init__(self, r, w, send: CipherState, recv: CipherState, attestation: dict):
        self.r, self.w, self._send, self._recv, self.attestation = r, w, send, recv, attestation

    async def send(self, data: bytes):
        for o in range(0, len(data), MAX_DATA):
            write_frame(self.w, self._send.encrypt(data[o:o + MAX_DATA]))
        await self.w.drain()

    async def recv(self) -> bytes:
        return self._recv.decrypt(await read_frame(self.r))

    def close(self):
        self.w.close()


async def open_stream(r: asyncio.StreamReader, w: asyncio.StreamWriter, target: str, verify: Verify, ticket: str = "") -> Stream:
    write_frame(w, json.dumps({"v": 1}).encode())
    await w.drain()
    att = json.loads(await read_frame(r))
    if "error" in att:
        raise RuntimeError(f"box: {att['error']}")
    rs = b64u_decode(att["static"])
    report = b64u_decode(att["report"]) if att.get("report") else b""
    if not report:
        if not verify.allow_dev:
            raise RuntimeError("box presented no attestation report")
        attestation = {"ok": False, "dev": True}
    else:
        attestation = verify_snp(report, rs, att["binding"], verify)
    hs = Handshake(PROLOGUE + hashlib.sha256(report).digest(), rs)
    write_frame(w, hs.write_message1(json.dumps({"target": target, "ticket": ticket}).encode()))
    await w.drain()
    ready = json.loads(hs.read_message2(await read_frame(r)))
    if not ready.get("ok"):
        raise RuntimeError(f"box refused: {ready.get('error')}")
    send, recv = hs.split()
    return Stream(r, w, send, recv, attestation)
