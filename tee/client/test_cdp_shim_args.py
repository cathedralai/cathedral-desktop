"""python3 tee/client/test_cdp_shim_args.py
The CDP shim must stop at start, with a message and a non-zero status, when it was given no choice
about which build to trust. Needs no Chrome and no box: it only starts the shim and looks at how it ends."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


def shim_safe(*extra):
    """Like shim, but a shim that kept running (it accepted the arguments) comes back as a failed run instead of an exception."""
    try:
        return shim(*extra)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(extra, 0, "", "the shim kept running")


def shim(*extra):
    # Port 0 and a box nobody listens on: a shim that gets past argument checks just sits and listens, so a
    # timeout is the failure signal.
    return subprocess.run([sys.executable, os.path.join(HERE, "cdp_shim.py"), "--box", "127.0.0.1:1", "--listen", "127.0.0.1:0", *extra],
                          capture_output=True, text=True, timeout=4)


try:
    r = shim()
    err = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else ""
    check("no fingerprint choice: exits non-zero", r.returncode != 0, f"status {r.returncode}")
    check("and the message names both ways out", "--measurement" in r.stderr and "--allow-any-measurement" in r.stderr, err)
    check("and it never starts listening", "listening" not in r.stderr)
except subprocess.TimeoutExpired:
    check("no fingerprint choice: exits non-zero", False, "the shim kept running")

# Same forms as the page: trimmed and lower-cased, then exactly 96 hex characters.
try:
    shim("--measurement", "AB" * 48)
    check("an upper-case --measurement is accepted at start", False, "exited")
except subprocess.TimeoutExpired:
    check("an upper-case --measurement is accepted at start", True, "still running when the timeout hit")
for label, bad in (("too short", "ab" * 47), ("not hex", "zz" * 48)):
    r = shim("--measurement", bad)
    check(f"a --measurement that is {label}: exits non-zero with a message", r.returncode != 0 and "fingerprint" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "")

for extra in (["--measurement", "ab" * 48], ["--allow-any-measurement"]):
    try:
        shim(*extra)
        check(f"{extra[0]} is accepted at start", False, "exited")
    except subprocess.TimeoutExpired:
        check(f"{extra[0]} is accepted at start", True, "still running when the timeout hit")

# ---- customer mode (AB#353 WP2): --customer-key refuses every waiver, by name, before the shim listens.
KEY = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"  # public test vector, tee/testdata/customer_host_data_v1.json
FP = ["--measurement", "ab" * 48]
for label, extra, words in (("--allow-any-measurement", [*FP, "--allow-any-measurement"], ("customer mode", "--allow-any-measurement")),
                            ("--allow-dev", [*FP, "--allow-dev"], ("customer mode", "--allow-dev")),
                            ("no --measurement", [], ("customer mode", "--measurement"))):
    try:
        r = shim_safe("--customer-key", KEY, *extra)
        check(f"--customer-key with {label}: exits non-zero and names the reason", r.returncode != 0 and all(w in r.stderr for w in words), r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
        check(f"--customer-key with {label}: never starts listening", "listening" not in r.stderr)
    except subprocess.TimeoutExpired:
        check(f"--customer-key with {label}: exits non-zero and names the reason", False, "the shim kept running")
for label, bad in (("empty", ""), ("not base64url", "!" * 43)):
    try:
        r = shim_safe("--customer-key", bad, *FP)
        check(f"--customer-key that is {label}: exits non-zero with a message", r.returncode != 0 and "invalid customer key" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
    except subprocess.TimeoutExpired:
        check(f"--customer-key that is {label}: exits non-zero with a message", False, "the shim kept running")
import json  # noqa: E402
import tempfile  # noqa: E402

sys.path.insert(0, HERE)
import mint_ticket  # noqa: E402

vec = json.load(open(os.path.join(HERE, "..", "testdata", "customer_host_data_v1.json")))
for h in vec["weak_keys"]["small_order_hex"] + vec["weak_keys"]["non_canonical_hex"]:
    wk = mint_ticket.b64u(bytes.fromhex(h))
    r = shim_safe("--customer-key", wk, *FP)
    check(f"--customer-key {h[:8]}..{h[-4:]} (weak): exits non-zero with a message", r.returncode != 0 and "invalid customer key" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")

with tempfile.TemporaryDirectory() as tmp:
    mine, other = os.path.join(tmp, "mine.key"), os.path.join(tmp, "other.key")
    for path in (mine, other):
        subprocess.run([sys.executable, os.path.join(HERE, "mint_ticket.py"), "keygen", "--out", path], check=True, capture_output=True)
    mine_pub = mint_ticket.b64u(open(os.path.join(tmp, "mine.pub"), "rb").read())
    r = shim_safe("--customer-key", mine_pub, *FP)
    check("--customer-key with no ticket source: exits non-zero and names --ticket-key", r.returncode != 0 and "--ticket-key" in r.stderr and "customer mode" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
    r = shim_safe("--customer-key", mine_pub, "--ticket-key", other, *FP)
    check("--customer-key with another key's --ticket-key: exits non-zero by name", r.returncode != 0 and "customer mode" in r.stderr and "ticket key" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
    r = shim_safe("--customer-key", mine_pub, "--ticket", "", *FP)
    check("--customer-key with an empty --ticket: exits non-zero by name", r.returncode != 0 and "customer mode" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
    try:
        shim("--customer-key", mine_pub, "--ticket-key", mine, *FP)
        check("--customer-key with its own --ticket-key and a fingerprint list is accepted at start", False, "exited")
    except subprocess.TimeoutExpired:
        check("--customer-key with its own --ticket-key and a fingerprint list is accepted at start", True, "still running when the timeout hit")



# ---- a key file that is missing, unreadable or not a key is a usage error: one line, exit 2, names the option, never the contents.
with tempfile.TemporaryDirectory() as tmp:
    secret = "SECRET-DO-NOT-PRINT-" * 3
    short, empty, unreadable = (os.path.join(tmp, n) for n in ("short.key", "empty.key", "locked.key"))
    open(short, "w").write(secret)
    open(empty, "w").close()
    with open(unreadable, "wb") as f:
        f.write(os.urandom(32))
    os.chmod(unreadable, 0)
    cases = [("missing file", os.path.join(tmp, "nope.key")), ("unreadable file", unreadable), ("wrong length", short), ("empty file", empty)]
    for mode, extra in (("without --customer-key", []), ("with --customer-key", ["--customer-key", KEY])):
        for label, path in cases:
            r = shim_safe(*extra, "--ticket-key", path, *FP)
            lines = [x for x in r.stderr.strip().splitlines() if x]
            check(f"--ticket-key {label}, {mode}: exit 2, no traceback, names the option, no contents",
                  r.returncode == 2 and "Traceback" not in r.stderr and "--ticket-key" in lines[-1] and "secret" not in r.stderr.lower() and "SECRET" not in r.stderr,
                  lines[-1] if lines else "no message")
    os.chmod(unreadable, 0o600)

print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
