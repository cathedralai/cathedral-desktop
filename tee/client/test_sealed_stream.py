"""python3 tee/client/test_sealed_stream.py path/to/boxd
Interop of the Python initiator with boxd -dev: handshake, JOB round trips inside the stream,
tamper detection, and refusal of a dev box when attestation is required."""
import asyncio
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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
        s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True))
        check("handshake with a dev box", s.attestation.get("dev") is True, f"{(time.monotonic() - t0) * 1000:.1f} ms")
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
    print("all checks passed" if not failures else f"{failures} failure(s)")
    sys.exit(1 if failures else 0)


asyncio.run(main())
