"""python3 tee/client/test_verify_snp.py
The Python verifier against the saved chip report in tee/fixtures: accepted as it is, accepted with
its own fingerprint pinned, refused with another fingerprint, refused when any signed byte, the
binding or the AMD root is wrong. No network and no box: the VCEK is the saved one."""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sealed_stream import Verify, verify_snp  # noqa: E402

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")
failures = 0


def read(name):
    with open(os.path.join(FX, name), "rb") as f:
        return f.read()


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


report = read("report.bin")
binding = read("binding.json").decode()
static_pub = base64.b64decode(json.loads(binding)["sealed_stream"]["x25519_public_b64"])
measurement = report[0x90:0xC0].hex()


def verify(rep=report, bind=binding, **kw):
    v = Verify(ark_der=kw.pop("ark_der", None), ask_der=read("amd-genoa-ask.der"), vcek_der=read("vcek.der"), **kw)
    return verify_snp(rep, static_pub, bind, v)


def refused(name, fn, pattern):
    try:
        fn()
        check(name, False, "accepted")
    except Exception as e:  # the verifier raises ValueError and cryptography's InvalidSignature
        msg = str(e) or type(e).__name__
        check(name, pattern in msg or pattern in type(e).__name__, msg)


r = verify(ark_der=read("amd-genoa-ark.der"))
check("saved report accepted, no fingerprint (test mode)", r["ok"] and r["test_mode"], f"measurement {r['measurement'][:16]}")

r = verify(ark_der=read("amd-genoa-ark.der"), allowed_measurements=[measurement])
check("its own fingerprint pinned: accepted, not test mode", r["ok"] and not r["test_mode"])

refused("another fingerprint pinned: refused",
        lambda: verify(ark_der=read("amd-genoa-ark.der"), allowed_measurements=["ff" + measurement[2:]]), "not an allowed fingerprint")

# A changed measurement byte is a change to signed bytes, so the chip signature is what refuses it.
flipped = bytearray(report)
flipped[0x90] ^= 0x01
refused("one flipped fingerprint bit refused", lambda: verify(bytes(flipped), ark_der=read("amd-genoa-ark.der")), "InvalidSignature")

wrong_binding = json.loads(binding)
wrong_binding["tls_spki_sha256"] = "0" * 64
refused("a binding that does not hash to REPORT_DATA refused",
        lambda: verify(bind=json.dumps(wrong_binding, sort_keys=True, separators=(",", ":"))), "REPORT_DATA")

# The ASK is not the pinned root, so the pin check refuses it before any signature is looked at.
refused("a wrong AMD root refused", lambda: verify(ark_der=read("amd-genoa-ask.der")), "pinned AMD")

print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
