"""python3 tee/client/test_tamper_relay.py path/to/boxd
The tamper relay against boxd -dev (AB#591): untouched frames pass, a flipped frame from the box is
refused by the client, and a flipped frame from the client makes boxd close the stream."""
import asyncio
import os
import subprocess
import sys

from cryptography.exceptions import InvalidTag

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sealed_stream import Verify, open_stream  # noqa: E402

BOXD = sys.argv[1] if len(sys.argv) > 1 else "./boxd"
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


async def relay(*args):
    """Start the relay on a free port; return the process and the port it bound."""
    p = await asyncio.create_subprocess_exec(sys.executable, os.path.join(HERE, "tamper_relay.py"),
                                             "--listen", "127.0.0.1:0", "--box", "127.0.0.1:38444", *args,
                                             stdout=asyncio.subprocess.PIPE)
    line = (await asyncio.wait_for(p.stdout.readline(), 10)).decode()
    return p, int(line.split()[1].rsplit(":", 1)[1])


async def stream_via(port):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    return await open_stream(r, w, target="job", verify=Verify(allow_dev=True))


async def tamper_line(p):
    try:
        return (await asyncio.wait_for(p.stdout.readline(), 5)).decode().strip()
    except asyncio.TimeoutError:
        return ""


async def main():
    box = subprocess.Popen([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:38443", "-stream", "127.0.0.1:38444"],
                           stderr=subprocess.PIPE, text=True)
    for line in box.stderr:
        if "LISTEN" in line:
            break
    procs = []
    try:
        # A frame number the stream never reaches: the relay is transparent.
        p, port = await relay("--frame", "1000")
        procs.append(p)
        s = await stream_via(port)
        replies = []
        for i in range(1, 4):
            await s.send(f"JOB {i}\n".encode())
            replies.append((await s.recv()).decode())
        check("untouched frames pass through the relay", replies == ["DONE 1 42\n", "DONE 2 42\n", "DONE 3 42\n"], str(replies))
        s.close()

        # Box to client, first DATA frame: the client must not accept the reply.
        p, port = await relay("--direction", "down", "--frame", "3")
        procs.append(p)
        s = await stream_via(port)
        await s.send(b"JOB 1\n")
        try:
            got = await asyncio.wait_for(s.recv(), 5)
            err = f"accepted {got!r}"
        except InvalidTag:
            err = "InvalidTag"
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        line = await tamper_line(p)
        check("relay flipped the box's first DATA frame", line.startswith("TAMPER flipped down frame 3 "), line)
        check("client refuses the flipped frame", err == "InvalidTag", err)
        s.close()

        # Client to box, first DATA frame: boxd must close, and nothing comes back.
        p, port = await relay("--direction", "up", "--frame", "3")
        procs.append(p)
        s = await stream_via(port)
        await s.send(b"JOB 1\n")
        try:
            got = await asyncio.wait_for(s.recv(), 5)
            err = f"accepted {got!r}"
        except asyncio.IncompleteReadError:
            err = "closed"
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"
        line = await tamper_line(p)
        check("relay flipped the client's first DATA frame", line.startswith("TAMPER flipped up frame 3 "), line)
        check("box closes the stream on the flipped frame", err == "closed", err)
        s.close()

        # The same box still serves a clean stream afterwards: a tamper costs one stream, not the box.
        p, port = await relay("--frame", "1000")
        procs.append(p)
        s = await stream_via(port)
        await s.send(b"JOB 7\n")
        check("box still serves a clean stream after the tampers", (await s.recv()) == b"DONE 7 42\n")
        s.close()
    finally:
        for p in procs:
            p.kill()
            await p.wait()
        box.kill()
    print("all checks passed" if not failures else f"{failures} failure(s)")
    sys.exit(1 if failures else 0)


asyncio.run(main())
