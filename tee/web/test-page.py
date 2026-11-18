"""python3 tee/web/test-page.py
The browser path without a TEE: boxd -dev, websockify relaying ws -> 8444 and serving tee/web, and a
headless Chromium (Playwright). Proves WebCrypto X25519 + AES-GCM in a real browser and frame
reassembly over a WebSocket relay (the library driven directly, with its own dev option), and that the
page refuses a box without attestation even when the link asks for dev. Needs BOXD env (or ./boxd), websockify and playwright in the venv, noVNC fetched."""
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
        # A link must not be able to switch attestation off: dev=1 is not a page option any more.
        page.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job&dev=1&nofp=1")
        page.wait_for_function("document.getElementById('link-text').textContent.startsWith('sealed') || document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        check("page refuses a dev box even when the link says dev=1", page.text_content("#link-text") == "refused" and "no attestation" in (page.text_content("#gone-detail") or ""), page.text_content("#gone-detail"))

        # The stream itself in a real browser (WebCrypto X25519 and AES-GCM, frames over a WebSocket relay):
        # the library is driven directly with its own dev option, since the page no longer offers one.
        proof = page.evaluate("""async () => {
            const { SealedStream, websocketPipe } = await import('./sealed-stream.js');
            const pipe = websocketPipe('ws://127.0.0.1:48080/websockify');
            await pipe.ready;
            const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
            const reply = new Promise((res) => { s.onmessage = (pt) => res(new TextDecoder().decode(pt)); });
            s.send(new TextEncoder().encode('JOB 1\\n'));
            const text = await reply;
            const dev = s.attestation && s.attestation.dev === true;
            s.close();
            return { text, dev };
        }""")
        check("library handshake through websockify to a dev box, in the browser", proof["dev"] is True, repr(proof))
        check("JOB answered inside the stream in the browser", proof["text"].strip() == "DONE 1 42", repr(proof["text"]))

        page2 = browser.new_page()
        page2.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job&nofp=1#ticket=not-a-real-ticket")
        page2.wait_for_function("document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        check("page refuses a dev box when attestation is required", "no attestation" in (page2.text_content("#gone-detail") or ""), page2.text_content("#gone-detail"))
        # The ticket is a bearer secret: it must not stay in the address bar, the history entry or a screenshot.
        check("the page removes the fragment from the address bar", page2.evaluate("location.hash") == "", page2.url)
        # No fingerprint choice in the link: the page says what to add, in link terms.
        page4 = browser.new_page()
        page4.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job")
        page4.wait_for_function("document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        why4 = page4.text_content("#gone-why") or ""
        check("a link with no fp= and no nofp=1 is refused in words that name both", "fp=" in why4 and "nofp=1" in why4, why4)
        # A ticket in the query is a link made wrong: the page drops it from the address bar and refuses, in words.
        page3 = browser.new_page()
        page3.goto("http://127.0.0.1:48080/index.html?relay=ws://127.0.0.1:48080/websockify&target=job&fp=ab&ticket=in-the-query&vncpw=pw")
        page3.wait_for_function("document.getElementById('link-text').textContent === 'refused'", timeout=15000)
        why = page3.text_content("#gone-why") or ""
        check("a ticket in the query is refused with where it belongs", "#" in why and "ticket" in why, why)
        check("the query ticket and password are removed from the address bar", "ticket=" not in page3.url and "vncpw=" not in page3.url, page3.url)
        browser.close()
finally:
    for p in procs:
        p.kill()
print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
