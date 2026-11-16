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
from sealed_stream import Verify, open_stream, read_frame, write_frame  # noqa: E402

BOXD = sys.argv[1] if len(sys.argv) > 1 else "./boxd"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


async def main():
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
