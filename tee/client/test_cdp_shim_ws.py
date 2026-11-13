"""python3 tee/client/test_cdp_shim_ws.py
The sealed stream and the CDP shim through a WebSocket relay, without a TEE: boxd -dev behind websockify
(the relay the browser page uses), then:
  1. open_stream over ws_pipe does three JOB round trips;
  2. a relay that answers in text is refused, not guessed at;
  3. a shim pointed at a dead relay closes the local connection and keeps listening;
  4. Playwright drives a local headless Chrome through the shim with --box ws://..., against a box that
     demands a fresh ticket per connection.
Needs: boxd (BOXD env or ./boxd), Chrome (CHROME env), websockets, websockify and playwright."""
import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
BOXD = os.environ.get("BOXD", "./boxd")
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
PY = sys.executable
procs = []
failures = 0

from sealed_stream import Verify, open_stream  # noqa: E402
from ws_pipe import open_ws_pipe  # noqa: E402


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


def start(cmd, ready=None):
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    procs.append(p)
    if ready:
        for line in p.stderr:
            if ready in line:
                break
    return p


def wait_port(port, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on {port}")


async def jobs_through_relay(url):
    r, w = await open_ws_pipe(url)
    s = await open_stream(r, w, target="job", verify=Verify(allow_dev=True))
    replies = []
    for i in range(1, 4):
        await s.send(f"JOB {i}\n".encode())
        replies.append((await s.recv()).decode())
    s.close()
    await w.wait_closed()
    check("three JOB round trips through websockify", replies == ["DONE 1 42\n", "DONE 2 42\n", "DONE 3 42\n"], str(replies))


async def text_relay_refused():
    from websockets.asyncio.server import serve

    async def speak_text(ws):
        await ws.send('{"v":1}')
        try:
            await ws.recv()
        except Exception:
            pass

    async with serve(speak_text, "127.0.0.1", 39480, subprotocols=["binary"]):
        r, w = await open_ws_pipe("ws://127.0.0.1:39480")
        try:
            await open_stream(r, w, target="job", verify=Verify(allow_dev=True))
            check("a relay that answers in text is refused", False, "handshake went through")
        except ValueError as e:
            check("a relay that answers in text is refused", "binary only" in str(e), str(e))


def dead_relay_closes_local():
    shim = start([PY, os.path.join(HERE, "cdp_shim.py"), "--box", "ws://127.0.0.1:1/none", "--listen", "127.0.0.1:39433",
                  "--allow-dev"], ready="listening")
    for attempt in (1, 2):
        c = socket.create_connection(("127.0.0.1", 39433), timeout=5)
        c.sendall(b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        try:
            data = c.recv(1)
        except socket.timeout:
            data = None
        c.close()
        check(f"dead relay: local connection {attempt} closed with no bytes", data == b"", repr(data))
    check("dead relay: shim still running", shim.poll() is None)


def drive(label, shim_port):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        t0 = time.monotonic()
        browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{shim_port}")
        t1 = time.monotonic()
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        page = ctx.new_page()
        page.set_content("<title>sealed relay ok</title><button id=b onclick=\"this.textContent='clicked'\">go</button>")
        page.click("#b")
        t2 = time.monotonic()
        title, text = page.title(), page.inner_text("#b")
        print(f"{label}: connect {(t1 - t0) * 1000:.0f} ms, page + click {(t2 - t1) * 1000:.0f} ms")
        check(label, title == "sealed relay ok" and text == "clicked", f"title={title!r} button={text!r}")
        browser.close()


try:
    start([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:39443", "-stream", "127.0.0.1:39444"], ready="LISTEN")
    start([PY, "-m", "websockify", "127.0.0.1:39080", "127.0.0.1:39444"])
    wait_port(39080)
    asyncio.run(jobs_through_relay("ws://127.0.0.1:39080"))
    asyncio.run(text_relay_refused())
    dead_relay_closes_local()

    start([CHROME, "--headless=new", "--remote-debugging-port=9655", "--remote-allow-origins=*", "--no-first-run",
           "--user-data-dir=/tmp/cdp-shim-ws-test-profile", "about:blank"])
    for _ in range(150):
        try:
            urllib.request.urlopen("http://127.0.0.1:9655/json/version", timeout=1).read()
            break
        except Exception:
            time.sleep(0.2)
    else:
        raise RuntimeError("Chrome never answered on 9655 (as root it needs --no-sandbox)")
    with tempfile.TemporaryDirectory() as tmp:
        key = os.path.join(tmp, "ticket.key")
        subprocess.run([PY, os.path.join(HERE, "mint_ticket.py"), "keygen", "--out", key], check=True, capture_output=True)
        start([BOXD, "-dev", "-ticket-key", os.path.join(tmp, "ticket.pub"),
               "-tls", "127.0.0.1:39543", "-stream", "127.0.0.1:39544", "-target-cdp", "127.0.0.1:9655"], ready="LISTEN")
        start([PY, "-m", "websockify", "127.0.0.1:39180", "127.0.0.1:39544"])
        wait_port(39180)
        start([PY, os.path.join(HERE, "cdp_shim.py"), "--box", "ws://127.0.0.1:39180", "--listen", "127.0.0.1:39533",
               "--ticket-key", key, "--allow-dev"], ready="listening")
        drive("Playwright through the shim over a WebSocket relay, ticket per connection", 39533)
finally:
    for p in procs:
        p.kill()

print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
