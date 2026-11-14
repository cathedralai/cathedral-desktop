"""python3 tee/client/test_sealed_stream.py path/to/boxd
Interop of the Python initiator with boxd -dev: handshake, JOB round trips inside the stream,
tamper detection, refusal of a dev box when attestation is required, and the ticket rules."""
import asyncio
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_ticket  # noqa: E402
import sealed_stream  # noqa: E402
from sealed_stream import Verify, open_stream, read_frame, write_frame  # noqa: E402

BOXD = sys.argv[1] if len(sys.argv) > 1 else "./boxd"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


async def customer_mode():
    """AB#353 WP2, no boxd: a fake box sends the saved chip report; check what the client does with a customer key.

    Handshake.write_message1 is wrapped only to read the plaintext of message 1 (the first message after HELLO)."""
    rd = lambda n: open(os.path.join(FX, n), "rb").read()  # noqa: E731
    with open(os.path.join(FX, "..", "testdata", "customer_host_data_v1.json")) as f:
        vec = json.load(f)
    key = vec["customer"]["public_key_b64u"]
    binding = rd("binding.json").decode()
    b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    static = base64.b64decode(json.loads(binding)["sealed_stream"]["x25519_public_b64"])
    report = rd("report.bin")
    measurement = report[0x90:0xC0].hex()
    att_full = json.dumps({"v": 1, "static": b64u(static), "report": b64u(report), "binding": binding}).encode()
    att_nore = json.dumps({"v": 1, "static": b64u(static)}).encode()
    kw = dict(ark_der=rd("amd-genoa-ark.der"), ask_der=rd("amd-genoa-ask.der"), vcek_der=rd("vcek.der"))
    listed = {"allowed_measurements": [measurement]}

    async def run(att=att_full, vkw=None, mint=None, tamper=None):
        """One connection to a fake box. Returns (error, frames the client wrote, plaintexts of message 1)."""
        got, payloads = [], []

        async def box(r, w):
            try:
                got.append(await read_frame(r))
                write_frame(w, att)
                await w.drain()
                got.append(await read_frame(r))  # message 1, if the client sends one
            except Exception:  # noqa: BLE001
                pass
            w.close()

        srv = await asyncio.start_server(box, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        orig = sealed_stream.Handshake.write_message1

        def spy(self, payload):
            payloads.append(payload)
            return orig(self, payload)

        sealed_stream.Handshake.write_message1 = spy
        err = None
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            try:
                v = Verify(**kw, **(vkw or {}))
                if tamper:
                    tamper(v)
                await open_stream(r, w, target="job", verify=v, mint=mint)
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
            w.close()
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        finally:
            sealed_stream.Handshake.write_message1 = orig
            srv.close()
            await srv.wait_closed()
        return err, got, payloads

    err, got, payloads = await run(vkw={"customer_key": key, **listed})
    check("customer key set, fixture HOST_DATA zero: refused with a named reason", "HOST_DATA is zero" in (err or ""), str(err))
    check("a refused check writes only HELLO, no message 1, no retry", len(got) == 1 and not payloads, f"frames {len(got)} message1 {len(payloads)}")
    errs = [(await run(vkw={"customer_key": key, **listed})) for _ in range(2)]
    check("a second open (reconnect) runs the customer check again", all("HOST_DATA is zero" in (e[0] or "") and len(e[1]) == 1 for e in errs), str([e[0] for e in errs]))

    # The waivers, set after the options were built so open_stream's own guard is what is under test. allow_dev skips verify_snp
    # entirely today, so it is tried against a box that presents no report.
    err, got, payloads = await run(att=att_nore, vkw={"customer_key": key, **listed}, tamper=lambda v: setattr(v, "allow_dev", True))
    check("customer key + allow_dev, box with no report: refused by name, no message 1", "customer mode refuses allow_dev" in (err or "") and not payloads, str(err))
    err, got, payloads = await run(vkw={"customer_key": key, **listed}, tamper=lambda v: setattr(v, "allow_dev", True))
    check("customer key + allow_dev, box with a report: refused by name", "customer mode refuses allow_dev" in (err or "") and not payloads, str(err))
    err, got, payloads = await run(vkw={"customer_key": key, **listed}, tamper=lambda v: setattr(v, "allow_any_measurement", True))
    check("customer key + allow_any_measurement: refused by name", "customer mode" in (err or "") and "allow_any_measurement" in (err or "") and not payloads, str(err))
    err, got, payloads = await run(vkw={"customer_key": key, **listed}, tamper=lambda v: setattr(v, "allowed_measurements", []))
    check("customer key + empty fingerprint list: refused by name", "customer mode needs a fingerprint list" in (err or "") and not payloads, str(err))

    # mint(rs) runs only after the report is verified: a failing report mints nothing and sends nothing after HELLO.
    minted = []

    def mint(rs):
        minted.append(rs)
        return "T"

    bad = bytearray(report)
    bad[0x90] ^= 1
    bad_att = json.dumps({"v": 1, "static": b64u(static), "report": b64u(bytes(bad)), "binding": binding}).encode()
    minted.clear()
    err, got, payloads = await run(att=bad_att, vkw={"allow_any_measurement": True}, mint=mint)
    check("a failing report: no ticket is minted and nothing is sent after HELLO", not minted and len(got) == 1 and not payloads and "report signature" in (err or ""), f"minted {len(minted)} frames {len(got)} {err}")
    minted.clear()
    err, got, payloads = await run(vkw={"customer_key": key, **listed}, mint=mint)
    check("a customer refusal also mints nothing", not minted and len(got) == 1, f"minted {len(minted)}")
    minted.clear()
    err, got, payloads = await run(vkw={"allow_any_measurement": True}, mint=mint)
    check("a good report: the ticket is minted once, for the box's static key, and message 1 carries it",
          minted == [static] and len(payloads) == 1 and json.loads(payloads[0])["ticket"] == "T", f"minted {len(minted)} {payloads}")

    err, got, payloads = await run(vkw={"allow_any_measurement": True})
    check("no customer key: message 1 is exactly {\"target\",\"ticket\"}, no customer field",
          len(payloads) == 1 and payloads[0] == b'{"target": "job", "ticket": ""}', str(payloads))
    try:
        check("message 1 payload with a key adds only the customer field",
              sealed_stream.message1_payload("job", "T", key) == json.dumps({"target": "job", "ticket": "T", "customer": key}).encode())
        check("message 1 payload without a key is byte for byte the old one",
              sealed_stream.message1_payload("job", "T") == json.dumps({"target": "job", "ticket": "T"}).encode())
    except Exception as e:  # noqa: BLE001
        check("message 1 payload", False, f"{type(e).__name__}: {e}")

    for label, bad_key in (("empty string", ""), ("not base64url", "!" * 43), ("31 bytes", b64u(bytes(31))), ("33 bytes", b64u(bytes(33)))):
        # The field is set after Verify is built, so the check in open_stream is what is under test.
        sent = []

        class W:
            def write(self, b):
                sent.append(b)

            async def drain(self):
                pass

            def close(self):
                pass

        v = Verify(**kw, **listed)
        v.customer_key = bad_key
        try:
            await asyncio.wait_for(open_stream(asyncio.StreamReader(), W(), target="job", verify=v), 2)
            check(f"customer key {label}: usage error before anything is written", False, "accepted")
        except ValueError as e:
            check(f"customer key {label}: usage error before anything is written", "invalid customer key" in str(e) and not sent, f"{e} writes {len(sent)}")
        except Exception as e:  # noqa: BLE001
            check(f"customer key {label}: usage error before anything is written", False, f"{type(e).__name__}: {e} writes {len(sent)}")


async def main():
    await customer_mode()
    box = subprocess.Popen([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:28443", "-stream", "127.0.0.1:28444"], stderr=subprocess.PIPE, text=True)
    for line in box.stderr:
        if "LISTEN" in line:
            break
    try:
        r, w = await asyncio.open_connection("127.0.0.1", 28444)
        t0 = time.monotonic()
        warned = io.StringIO()
        with contextlib.redirect_stderr(warned):
            s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True))
        check("handshake with a dev box", s.attestation.get("dev") is True, f"{(time.monotonic() - t0) * 1000:.1f} ms")
        check("accepting a box with no attestation prints a warning", "WARNING" in warned.getvalue() and "attestation" in warned.getvalue(), warned.getvalue().strip())
        replies = []
        for i in range(1, 4):
            await s.send(f"JOB {i}\n".encode())
            replies.append((await s.recv()).decode())
        check("three JOB round trips", replies == ["DONE 1 42\n", "DONE 2 42\n", "DONE 3 42\n"], str(replies))
        s.close()

        r, w = await asyncio.open_connection("127.0.0.1", 28444)
        s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True))
        await s.send(b"JOB 9\n")
        ct = bytearray(await read_frame(r))
        ct[-1] ^= 1
        try:
            s._recv.decrypt(bytes(ct))
            check("tampered frame refused", False)
        except Exception as e:
            check("tampered frame refused", True, type(e).__name__)
        s.close()

        r, w = await asyncio.open_connection("127.0.0.1", 28444)
        try:
            await open_stream(r, w, target="job", verify=Verify())
            check("dev box refused when attestation required", False)
        except RuntimeError as e:
            check("dev box refused when attestation required", "no attestation" in str(e), str(e))
        w.close()
    finally:
        box.kill()
    await tickets()
    print("all checks passed" if not failures else f"{failures} failure(s)")
    sys.exit(1 if failures else 0)


async def tickets():
    """A box that pins a mint key: what it accepts and what it refuses.

    Still ``-dev`` (no SEV-SNP here), so the attestation is skipped and the
    ticket is the only gate under test.
    """
    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "ticket.key")
        subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "mint_ticket.py"),
                        "keygen", "--out", key_path], check=True, capture_output=True)
        key = mint_ticket.load_key(key_path)
        box = subprocess.Popen([BOXD, "-dev", "-ticket-key", os.path.join(tmp, "ticket.pub"),
                                "-tls", "127.0.0.1:28543", "-stream", "127.0.0.1:28544"],
                               stderr=subprocess.PIPE, text=True)
        for line in box.stderr:
            if "LISTEN" in line:
                break
        try:
            static = await mint_ticket.box_static_key("127.0.0.1", 28544)

            async def attempt(ticket):
                r, w = await asyncio.open_connection("127.0.0.1", 28544)
                try:
                    s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True), ticket=ticket)
                    await s.send(b"JOB 1\n")
                    reply = (await s.recv()).decode()
                    s.close()
                    return reply
                except RuntimeError as exc:
                    w.close()
                    return f"refused: {exc}"

            good = mint_ticket.issue(key, box_static=static, target="job")
            check("a minted ticket opens the stream", await attempt(good) == "DONE 1 42\n")
            check("the same ticket twice is refused", "refused" in await attempt(good))

            # The reason tickets carry a nonce: two minted in one second used to be
            # byte-identical, so the second looked like a replay of the first and
            # anything opening streams in parallel (CDP) lost every one but the first.
            pair = [mint_ticket.issue(key, box_static=static, target="job") for _ in range(2)]
            check("two tickets minted in the same second differ", pair[0] != pair[1])
            answers = await asyncio.gather(*(attempt(t) for t in pair))
            check("both open their own stream", answers == ["DONE 1 42\n"] * 2, str(answers))

            other = bytes(32)
            check("a ticket minted for another box is refused",
                  "refused" in await attempt(mint_ticket.issue(key, box_static=other, target="job")))
            check("a ticket for another target is refused",
                  "refused" in await attempt(mint_ticket.issue(key, box_static=static, target="vnc")))

            body = json.dumps({"box": base64.b64encode(static).decode(), "exp": int(time.time()) + 120,
                               "target": "job"}, separators=(",", ":"), sort_keys=True).encode()
            b64u = mint_ticket.b64u
            check("a ticket with no nonce is refused",
                  "refused" in await attempt(f"{b64u(body)}.{b64u(key.sign(body))}"))

            far = json.dumps({"box": base64.b64encode(static).decode(), "exp": int(time.time()) + 3600,
                              "nonce": b64u(os.urandom(16)), "target": "job"},
                             separators=(",", ":"), sort_keys=True).encode()
            check("an expiry past 10 minutes is refused",
                  "refused" in await attempt(f"{b64u(far)}.{b64u(key.sign(far))}"))

            stranger = mint_ticket.Ed25519PrivateKey.generate()
            check("a ticket from an unpinned mint is refused",
                  "refused" in await attempt(mint_ticket.issue(stranger, box_static=static, target="job")))

            # minter() is the path every client takes: a fresh ticket per connection.
            mint = mint_ticket.minter(key_path, "job")
            r, w = await asyncio.open_connection("127.0.0.1", 28544)
            s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True), mint=mint)
            await s.send(b"JOB 7\n")
            check("open_stream mints its own ticket", (await s.recv()).decode() == "DONE 7 42\n")
            s.close()
            r, w = await asyncio.open_connection("127.0.0.1", 28544)
            s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True), mint=mint)
            await s.send(b"JOB 8\n")
            check("and again on the next connection", (await s.recv()).decode() == "DONE 8 42\n")
            s.close()
        finally:
            box.kill()


asyncio.run(main())
