# Sealed stream v1

A byte pipe into a TEE box whose far end is proven by AMD, over any relay. The browser (or a
native client) verifies the box's SEV-SNP report, agrees a session key with the box, and then
every frame is AES-GCM ciphertext. Relays (websockify, the hotel bridge, a Cloudflare Worker, a
tunnel) carry opaque frames and learn nothing but their sizes and timing.

Built on the AB#361 link: the box makes a fresh ECDSA P-256 key at boot and gets an SNP report
with `REPORT_DATA = sha256(SPKI) || 0x00 * 32` through configfs-tsm. That key signs the handshake.

Private track (M-H, AB#353). Not production. Draft, 6 Nov 2026.

## Ports in the box

| Port | Protocol | Who |
|---|---|---|
| 8443 | TLS 1.3 line protocol from AB#361 (`JOB`, `REPORT`); unchanged | host harness, native clients that pin the cert |
| 8444 | sealed stream (this document), plain TCP | browsers through a relay, native clients |

Targets a stream can open: `vnc` (127.0.0.1:5901), `cdp` (127.0.0.1:9222), `job` (the box's own
`JOB` handler, for tests).

## Framing

Every message on the wire is `u32 big-endian length || payload`, length at most 1 MiB. Handshake
payloads are JSON with bytes as base64url (no padding). Data payloads are ciphertext.

## Handshake

```
C -> B   HELLO   {"v":1, "nonce_c":b64(32), "eph_c":b64(X25519 pub)}
B -> C   ATTEST  {"v":1, "nonce_b":b64(32), "eph_b":b64(X25519 pub), "spki":b64(box P-256 SPKI DER),
                  "report":b64(SNP report, 1184 bytes), "certs":{"vcek":b64 DER,"ask":b64 DER,"ark":b64 DER} (optional),
                  "sig":b64(ECDSA P-256 SHA-256 signature, ASN.1 DER, over T1)}
C -> B   OPEN    AES-GCM(k_c2b, n(c,0), {"target":"vnc"|"cdp"|"job", "ticket":b64 or ""}, aad = H1)
B -> C   READY   AES-GCM(k_b2c, n(b,0), {"ok":true} or {"ok":false,"error":"..."}, aad = H1)
then     DATA    AES-GCM(k_dir, n(dir,i), bytes, aad = dir byte), i from 1, each direction its own counter
```

Transcript: `T1 = "sealed-stream/v1" || nonce_c || nonce_b || eph_c || eph_b || spki`, `H1 = sha256(T1)`.

Keys: `ss = X25519(eph_c_priv, eph_b)`; `prk = HKDF-Extract(salt = H1, ikm = ss)`;
`k_c2b = HKDF-Expand(prk, "sealed-stream/v1 c2b", 32)`; `k_b2c = HKDF-Expand(prk, "sealed-stream/v1 b2c", 32)`.
HMAC-SHA-256 throughout.

Nonces: 12 bytes, `dir || 0x00 * 3 || u64 big-endian counter`, `dir` = 0x01 client to box, 0x02 box
to client. OPEN and READY use counter 0; data starts at 1. A counter never repeats under one key;
at 2^63 the side closes.

## What the client verifies before it sends OPEN

1. `report[0x50:0x90] == sha256(spki) || 0x00 * 32` (the key in the handshake is the attested key).
2. The report signature (ECDSA P-384, SHA-384, over `report[:0x2A0]`; r and s are 72-byte
   little-endian fields at 0x2A0 and 0x2E8) verifies with the VCEK.
3. VCEK is signed by ASK, ASK by ARK, ARK by itself (RSA-PSS, SHA-384, salt 48), and the ARK's SPKI
   hash equals the pinned AMD Genoa root (`tee/fixtures/amd-genoa-ark.der`). VCEK comes from the
   box's `certs`, or from AMD KDS by chip id and TCB (`report[0x1A0:0x1E0]`, `report[0x180:0x188]`)
   through a cache the client is given, never from the relay's say-so.
4. `report[0x90:0xC0]` (MEASUREMENT) is in the client's allowed list: the fingerprint AB#363
   publishes. An empty list is a test mode and is shown as such.
5. `sig` verifies over T1 with the key in `spki`.

Only then is `ss` derived. A client that cannot verify shows why and never sends OPEN.

## Ticket

The box authenticates the client with the ticket inside OPEN: Ed25519 signature by Cathedral over
`{"room":..., "target":..., "exp":unix}` with the public key pinned in the box image. A box started
with `-noticket` accepts an empty ticket; that mode exists for the private spike only and the box
prints `NOTICKET` on its console at boot.

## Threats this covers and does not

- Covered: a relay or network that reads or alters frames; a box that is not the measured image
  (measurement check); a box whose key is not the attested one (REPORT_DATA binding); replay of a
  handshake (fresh nonces and ephemeral keys on both sides).
- Not covered: the host that runs the VM denying service; a client that chooses to accept any
  measurement; the trust Cathedral's control plane keeps over the box's lifecycle. gVisor is not in
  this path: the box is the room.

## Implementation

- Box: `tee/boxd/main.go`, Go standard library only (X25519 via crypto/ecdh, HKDF via crypto/hmac),
  so it builds on c48 without module downloads. `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`.
- Browser: `tee/web/sealed-stream.js` (WebCrypto only; a WebSocket-shaped object that noVNC's
  `RFB` accepts as its transport) and `tee/web/snp-verify.js` (DER walker, chain and report checks).
- Native: `tee/client/sealed_stream.py` (cryptography lib), used by the CDP shim that gives
  Playwright a local `ws://` endpoint.
- Relay for the spike: `websockify PORT BOX_IP:8444` on the host; it needs no change.
