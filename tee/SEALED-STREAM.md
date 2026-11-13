# Sealed stream v1

A byte pipe into a TEE box whose far end is proven by AMD, over any relay. The client (a browser or
a native program) verifies the box's SEV-SNP report, runs a Noise handshake against the static key
that report binds, and from then on every frame is AES-GCM ciphertext. Relays (websockify, the hotel
bridge, a Cloudflare Worker, a tunnel) carry opaque frames and learn only sizes and timing.

Built on the AB#361 link (fresh keys per boot, report through configfs-tsm). Private track (M-H,
AB#353, cards AB#591 to AB#593). Not production. 6 Nov 2026.

## Ports in the box

| Port | Protocol | Who |
|---|---|---|
| 8443 | TLS 1.3 line protocol from AB#361 (`JOB`, `REPORT`), unchanged | host harness, native clients that pin the cert |
| 8444 | sealed stream (this document), plain TCP | browsers through a relay, native clients |

Targets: `vnc` (127.0.0.1:5901), `cdp` (127.0.0.1:9222), `job` (the box's own `JOB` handler, for
tests). Addresses are flags on boxd (`-target-vnc`, `-target-cdp`).

## Key binding

The box makes two keys at boot: the AB#361 ECDSA P-256 TLS key and a static X25519 key for the
stream. Both are named in one binding object, the layout sealed secrets and the miner hotels use
(cathedral-sandbox `docs/SEALED_SECRETS.md`):

```
binding = {"sealed_stream":{"schema":"sealed-stream/v1","x25519_public_b64":"<32 bytes, base64>"},
           "tls_spki_sha256":"<hex>"}
REPORT_DATA = sha256(canonical(binding)) || 0x00 * 32
```

canonical = sorted keys, compact separators, raw UTF-8 (Python `json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=False)`; Go `encoding/json` with HTML escaping off). The box
sends the canonical string itself, so the client hashes exactly those bytes. One verifier serves
every lane; a `sealed_secrets` object sits beside `sealed_stream` when both ride in one box.

## Framing

Every message on the wire is `u32 big-endian length || payload`, at most 1 MiB. Pre-handshake
payloads are JSON with bytes as base64url (no padding). Handshake and data payloads are Noise.

## Handshake: Noise_NK_25519_AESGCM_SHA256

```
C -> B   HELLO   {"v":1}
B -> C   ATTEST  {"v":1, "static":b64u(X25519 pub), "binding":"<canonical JSON>", "report":b64u(SNP report),
                  "certs":{"vcek","ask","ark"} (optional), "dev":true (no report; test boxes only)}
         client verifies the report (below) and that binding.sealed_stream names `static`
C -> B   NK msg 1  e, es   payload {"target":"vnc"|"cdp"|"job", "ticket":"..."}   (encrypted under es)
B -> C   NK msg 2  e, ee   payload {"ok":true} or {"ok":false,"error":"..."}      (key confirmation)
then     DATA      AES-GCM frames from Split(): initiator sends with k1, responder with k2
```

Prologue = `"sealed-stream/v1" || sha256(report)`, so the handshake hash binds the report. The
target and ticket travel inside the first encrypted payload: never a bare first byte. Nothing is
piped to 5901 or 9222 before message 2 confirms the keys.

Nonces: 96 bits, `0x00 * 4 || u64 big-endian counter`, strictly in order; any gap or failed tag
closes the stream. Max data frame 64 KiB. Rekey (Noise `REKEY`) every 2^20 frames per direction.

## What the client verifies before NK message 1

1. `sha256(binding bytes) || 0 * 32 == REPORT_DATA`, and `binding.sealed_stream.x25519_public_b64`
   equals the static key presented (and `tls_spki_sha256` when the caller knows the TLS key).
2. The report signature (ECDSA P-384, SHA-384, over `report[:0x2A0]`; r and s are 72-byte
   little-endian fields at 0x2A0 and 0x2E8) verifies with the VCEK.
3. VCEK signed by ASK, ASK by ARK, ARK by itself (RSA-PSS, SHA-384, salt 48), and sha256 of the ARK
   certificate DER equals the pin ctcli uses: Genoa `4c6598d1…3db2f1`, Milan `69d063b4…540bcd`.
   VCEK comes from the box's `certs` or from AMD KDS by chip id and TCB through a cache the client owns.
4. MEASUREMENT (`report[0x90:0xC0]`) is in the client's allowed list, the fingerprint AB#363
   publishes. An empty list is test mode and is shown as such, never as a pass.

A client that cannot verify shows why and sends nothing further.

## Ticket

NK gives the client's first message no freshness from the box, so a captured message 1 could be
replayed to reopen the target. The ticket closes that: Ed25519 by Cathedral over
`{"box","exp","nonce","target"}` as `base64url(JSON) "." base64url(sig)`, verified with the key
pinned in the box, and refused unless all four hold:

- `box` equals the box's own Noise static key, base64 as the binding spells it. The key is per boot
  and per box, it is what REPORT_DATA commits to, and ATTEST hands it to the client before any
  ticket is asked for, so a minter can always name it. A room id cannot do this job: it would have
  to reach the box on its measured command line, which would give every box its own measurement,
  and a ticket naming nothing opens every box that pins the same mint key.
- `target` equals the requested target.
- `exp` is at most 10 minutes ahead.
- `nonce` is present. Without it two tickets minted in the same second for one target are
  byte-identical and the second is refused as its own replay, which is what parallel connections
  (CDP opens several) look like.

Single use: the box remembers used tickets until they expire and refuses a repeat
(`TICKET replay refused` on the console; `TICKET for another box refused` and `TICKET without a
nonce refused` for the other two). One ticket is one stream, so a client that opens streams as it
goes mints as it goes (`mint_ticket.minter` passed to `open_stream(mint=...)`). A box started with
`-noticket` accepts an empty ticket; that mode is for the private spike only and the box prints
`NOTICKET` at boot.

## Threats covered and not

- Covered: a relay or network that reads or alters frames; a box that is not the measured image
  (measurement check); a box whose key is not the attested one (binding check); replay of the
  handshake (single-use ticket); a client that was never attested to (it fails closed).
- Not covered: the host that runs the VM denying service; a client that chooses an empty
  measurement list; Cathedral's control plane keeping the box's lifecycle. gVisor is not in this
  path: the box is the room.

## Implementation and tests

- Box: `tee/boxd/` (Go, standard library only; `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build`).
- Browser: `tee/web/sealed-stream.js` (Noise NK with WebCrypto; `SealedStream.websocketLike()` is a
  WebSocket-shaped transport for noVNC's `RFB`) and `tee/web/snp-verify.js` (DER walker, chain and
  report checks). Tests: `node tee/web/test-snp-verify.mjs`, `node tee/web/test-sealed-stream.mjs BOXD`.
- Native: `tee/client/sealed_stream.py` (cryptography lib) and `tee/client/cdp_shim.py`, a local
  TCP listener that opens one stream per connection so Playwright's `connect_over_cdp` and
  browser-use work unchanged. `--box` takes `HOST:PORT` or a `ws://`/`wss://` relay URL
  (`tee/client/ws_pipe.py`, one WebSocket per connection). Tests: `tee/client/test_sealed_stream.py BOXD`,
  `tee/client/test_cdp_shim.py`, `tee/client/test_cdp_shim_ws.py` (through websockify).
- Relay for the spike: `websockify PORT BOX_IP:8444` on the host; it needs no change.

Measured on the Mac against `boxd -dev` (no TEE, loopback): handshake 4 to 23 ms native, Playwright
connect 98 ms, click 94 ms, two property reads 5 ms, all through the stream.
