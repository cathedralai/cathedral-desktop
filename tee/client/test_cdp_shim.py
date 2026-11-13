"""python3 tee/client/test_cdp_shim.py
End to end without a TEE: a local headless Chrome on 9222 stands in for the box's Chromium, boxd -dev
pipes target cdp to it, the shim listens on 9333, and Playwright drives the browser through the sealed
stream. Runs twice, once on a box with no ticket and once on a box that demands one, since Chromium
opens a connection per target and a ticket is single use. Prints per-action latency.
Needs: boxd (BOXD env or ./boxd), Google Chrome, playwright."""
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BOXD = os.environ.get("BOXD", "./boxd")
CHROME = os.environ.get("CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
PY = sys.executable
procs = []


def start(cmd, ready=None, **kw):
    p = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True, **kw)
    procs.append(p)
    if ready:
        for line in p.stderr:
            if ready in line:
                break
    return p


def drive(label, shim_port):
    """Connect Playwright through the shim and use the page. Returns True if it worked."""
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        t0 = time.monotonic()
        browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{shim_port}")
        t1 = time.monotonic()
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        page = ctx.new_page()
        page.set_content("<title>sealed stream ok</title><button id=b onclick=\"this.textContent='clicked'\">go</button>")
        t2 = time.monotonic()
        page.click("#b")
        t3 = time.monotonic()
        title, text = page.title(), page.inner_text("#b")
        t4 = time.monotonic()
        print(f"{label}: connect {(t1 - t0) * 1000:.0f} ms, new page + content {(t2 - t1) * 1000:.0f} ms, "
              f"click {(t3 - t2) * 1000:.0f} ms, two reads {(t4 - t3) * 1000:.0f} ms")
        ok = title == "sealed stream ok" and text == "clicked"
        print(("ok   " if ok else "FAIL ") + f"{label}: title={title!r} button={text!r}")
        browser.close()
        return ok


try:
    start([CHROME, "--headless=new", "--remote-debugging-port=9555", "--remote-allow-origins=*", "--no-first-run", "--user-data-dir=/tmp/cdp-shim-test-profile", "about:blank"])
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:9555/json/version", timeout=1).read(); break
        except Exception:
            time.sleep(0.2)
    start([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:38443", "-stream", "127.0.0.1:38444", "-target-cdp", "127.0.0.1:9555"], ready="LISTEN")
    start([PY, os.path.join(HERE, "cdp_shim.py"), "--box", "127.0.0.1:38444", "--listen", "127.0.0.1:9333", "--allow-dev", "--allow-any-measurement"], ready="listening")
    results = [drive("no ticket", 9333)]

    # The same run against a box that demands a ticket. One --ticket would open the
    # first connection and nothing after it, so the shim mints per connection.
    with tempfile.TemporaryDirectory() as tmp:
        key = os.path.join(tmp, "ticket.key")
        subprocess.run([PY, os.path.join(HERE, "mint_ticket.py"), "keygen", "--out", key], check=True, capture_output=True)
        start([BOXD, "-dev", "-ticket-key", os.path.join(tmp, "ticket.pub"),
               "-tls", "127.0.0.1:38543", "-stream", "127.0.0.1:38544", "-target-cdp", "127.0.0.1:9555"], ready="LISTEN")
        start([PY, os.path.join(HERE, "cdp_shim.py"), "--box", "127.0.0.1:38544", "--listen", "127.0.0.1:9433",
               "--ticket-key", key, "--allow-dev", "--allow-any-measurement"], ready="listening")
        results.append(drive("ticket per connection", 9433))

    sys.exit(0 if all(results) else 1)
finally:
    for p in procs:
        p.kill()
