"""python3 tee/client/test_cdp_shim.py
End to end without a TEE: a local headless Chrome on 9222 stands in for the box's Chromium, boxd -dev
pipes target cdp to it, the shim listens on 9333, and Playwright drives the browser through the sealed
stream. Prints per-action latency. Needs: boxd (BOXD env or ./boxd), Google Chrome, playwright."""
import os
import subprocess
import sys
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


try:
    start([CHROME, "--headless=new", "--remote-debugging-port=9555", "--remote-allow-origins=*", "--no-first-run", "--user-data-dir=/tmp/cdp-shim-test-profile", "about:blank"])
    for _ in range(50):
        try:
            urllib.request.urlopen("http://127.0.0.1:9555/json/version", timeout=1).read(); break
        except Exception:
            time.sleep(0.2)
    start([BOXD, "-dev", "-noticket", "-tls", "127.0.0.1:38443", "-stream", "127.0.0.1:38444", "-target-cdp", "127.0.0.1:9555"], ready="LISTEN")
    start([PY, os.path.join(HERE, "cdp_shim.py"), "--box", "127.0.0.1:38444", "--listen", "127.0.0.1:9333", "--allow-dev"], ready="listening")
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        t0 = time.monotonic()
        browser = pw.chromium.connect_over_cdp("http://127.0.0.1:9333")
        t1 = time.monotonic()
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        page = ctx.new_page()
        page.set_content("<title>sealed stream ok</title><button id=b onclick=\"this.textContent='clicked'\">go</button>")
        t2 = time.monotonic()
        page.click("#b")
        t3 = time.monotonic()
        title, label = page.title(), page.inner_text("#b")
        t4 = time.monotonic()
        print(f"connect {(t1 - t0) * 1000:.0f} ms, new page + content {(t2 - t1) * 1000:.0f} ms, click {(t3 - t2) * 1000:.0f} ms, two reads {(t4 - t3) * 1000:.0f} ms")
        ok = title == "sealed stream ok" and label == "clicked"
        print(("ok   " if ok else "FAIL ") + f"Playwright through the sealed stream: title={title!r} button={label!r}")
        browser.close()
        sys.exit(0 if ok else 1)
finally:
    for p in procs:
        p.kill()
