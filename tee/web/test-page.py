"""python3 tee/web/test-page.py
The browser path without a TEE: boxd -dev, websockify relaying ws -> 8444 and serving tee/web, and a
headless Chromium (Playwright) loading index.html with target=job. Proves WebCrypto X25519 + AES-GCM
in a real browser, frame reassembly over a WebSocket relay, and the page's refusal when attestation
is required. Needs BOXD env (or ./boxd), websockify and playwright in the venv, noVNC fetched."""
import os
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BOXD = os.environ.get("BOXD", "./boxd")
PY = sys.executable
procs = []


def start(cmd, ready=None):
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    procs.append(p)
    if ready:
        for line in p.stderr:
            if ready in line:
                break
    return p


def wait_port(port, timeout=15):
    # A fixed sleep is a race on a slow runner; the page load must not start before websockify listens.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing listening on 127.0.0.1:{port} after {timeout} s")


failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


try:
    start([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:48443", "-stream", "127.0.0.1:48444"], ready="LISTEN")
    start([PY, "-m", "websockify", "--web", HERE, "127.0.0.1:48080", "127.0.0.1:48444"])
    wait_port(48080)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        browser = pw.chromium.launch(channel="chrome")
        page = browser.new_page()
        logs = []
        page.on("console", lambda m: logs.append(m.text))
        page.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job&dev=1")
        page.wait_for_function("document.getElementById('link-text').textContent.startsWith('sealed') || document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        link = page.text_content("#link-text")
        page.wait_for_function("document.querySelector('#screen pre') !== null", timeout=5000)
        reply = page.text_content("#screen pre")
        check("browser handshake through websockify to a dev box", link == "sealed job", f"link={link!r} attest={page.text_content('#attest-text')!r}")
        check("JOB answered inside the stream in the browser", reply.strip() == "DONE 1 42", repr(reply))

        page2 = browser.new_page()
        page2.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job")
        page2.wait_for_function("document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        check("page refuses a dev box when attestation is required", "no attestation" in (page2.text_content("#gone-detail") or ""), page2.text_content("#gone-detail"))
        browser.close()
finally:
    for p in procs:
        p.kill()
print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
