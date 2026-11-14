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
        r = shim("--customer-key", KEY, *extra)
        check(f"--customer-key with {label}: exits non-zero and names the reason", r.returncode != 0 and all(w in r.stderr for w in words), r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
        check(f"--customer-key with {label}: never starts listening", "listening" not in r.stderr)
    except subprocess.TimeoutExpired:
        check(f"--customer-key with {label}: exits non-zero and names the reason", False, "the shim kept running")
for label, bad in (("empty", ""), ("not base64url", "!" * 43)):
    try:
        r = shim("--customer-key", bad, *FP)
        check(f"--customer-key that is {label}: exits non-zero with a message", r.returncode != 0 and "invalid customer key" in r.stderr, r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "no message")
    except subprocess.TimeoutExpired:
        check(f"--customer-key that is {label}: exits non-zero with a message", False, "the shim kept running")
try:
    shim("--customer-key", KEY, *FP)
    check("--customer-key with a fingerprint list is accepted at start", False, "exited")
except subprocess.TimeoutExpired:
    check("--customer-key with a fingerprint list is accepted at start", True, "still running when the timeout hit")


print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
