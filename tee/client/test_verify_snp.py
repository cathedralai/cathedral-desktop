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


# The chip certificate names its firmware in four AMD extensions (12, 0, 28, 88 for the saved chip); they
# must equal the report's own numbers at 0x180, 0x181, 0x186, 0x187, and that check runs before the
# report's signature, so a changed byte is named as a firmware mismatch.
for off, part in ((0x180, "bl"), (0x181, "tee"), (0x186, "snp"), (0x187, "ucode")):
    bad = bytearray(report)
    bad[off] ^= 0x01
    refused(f"firmware byte {part} changed: refused",
            lambda bad=bad: verify(bytes(bad), ark_der=read("amd-genoa-ark.der"), allow_any_measurement=True), f"firmware {part}")

# min_tcb is a floor on the reported numbers, checked after the signature; parts left out are not checked.
tcb = {"bl": report[0x180], "tee": report[0x181], "snp": report[0x186], "ucode": report[0x187]}
r = verify(ark_der=read("amd-genoa-ark.der"), allow_any_measurement=True, min_tcb=dict(tcb))
check("floor equal to the reported firmware: accepted", r["ok"], str(tcb))
for part in tcb:
    refused(f"floor one above the reported {part}: refused",
            lambda part=part: verify(ark_der=read("amd-genoa-ark.der"), allow_any_measurement=True, min_tcb={part: tcb[part] + 1}),
            f"below the floor: {part}")

# The floor is checked for shape before anything is compared: only the four part names, each an integer 0 to 255.
# A part left out means no floor for that part (the other parts still apply). Same messages as the browser verifier.
ARK = read("amd-genoa-ark.der")
for label, floor in (("an unknown key", {"snp": 1, "bogus": 1}), ("NaN", {"snp": float("nan")}), ("a negative", {"snp": -1}),
                     ("a float", {"snp": 1.5}), ("a string", {"snp": "5"}), ("over 255", {"snp": 256}), ("None", {"snp": None}),
                     ("a bool", {"snp": True}), ("a list", [1, 2, 3, 4]), ("a number", 5), ("a string instead of a dict", "snp")):
    refused(f"floor with {label}: refused", lambda floor=floor: verify(ark_der=ARK, allow_any_measurement=True, min_tcb=floor), "invalid TCB floor")
r = verify(ark_der=ARK, allow_any_measurement=True, min_tcb={"snp": 28})
check("floor with one part only: the others are not checked", r["ok"])
r = verify(ark_der=ARK, allow_any_measurement=True, min_tcb={})
check("an empty floor dict is no floor", r["ok"])

# Fingerprints: trimmed and lower-cased, then exactly 96 hex characters; anything else is refused up front.
r = verify(ark_der=ARK, allowed_measurements=[f"  {measurement.upper()}\n"])
check("an upper-case, padded fingerprint is accepted", r["ok"] and not r["test_mode"])
for label, bad in (("too short", measurement[:94]), ("too long", measurement + "00"), ("not hex", "zz" + measurement[2:]), ("empty", "")):
    refused(f"fingerprint {label}: refused", lambda bad=bad: verify(ark_der=ARK, allowed_measurements=[measurement, bad]), "invalid fingerprint")

for label, kw in (("no list", {}), ("empty list", {"allowed_measurements": []}), ("allow_any_measurement false", {"allow_any_measurement": False})):
    refused(f"{label}: refused", lambda kw=kw: verify(ark_der=read("amd-genoa-ark.der"), **kw), "fingerprint")

r = verify(ark_der=read("amd-genoa-ark.der"), allow_any_measurement=True)
check("allow_any_measurement: accepted and still reported as test mode", r["ok"] and r["test_mode"], f"measurement {r['measurement'][:16]}")

r = verify(ark_der=read("amd-genoa-ark.der"), allowed_measurements=[measurement])
check("its own fingerprint pinned: accepted, not test mode", r["ok"] and not r["test_mode"])

refused("another fingerprint pinned: refused",
        lambda: verify(ark_der=read("amd-genoa-ark.der"), allowed_measurements=["ff" + measurement[2:]]), "not an allowed fingerprint")

# A changed measurement byte is a change to signed bytes, so the chip signature is what refuses it.
flipped = bytearray(report)
flipped[0x90] ^= 0x01
refused("one flipped fingerprint bit refused", lambda: verify(bytes(flipped), ark_der=read("amd-genoa-ark.der")), "InvalidSignature")

# Policy bits are signed, so the policy refusal has to come before the signature check for the message
# to name the policy. Bit 19 is debug and bit 18 is migration: byte 10 of the report, 0x08 and 0x04.
for bit, word in ((0x08, "debug"), (0x04, "migration")):
    bad = bytearray(report)
    bad[10] |= bit
    refused(f"{word} policy bit refused", lambda bad=bad: verify(bytes(bad), ark_der=read("amd-genoa-ark.der")), word)
check("saved report policy has neither bit", report[10] & 0x0C == 0, f"policy {report[8:16][::-1].hex()}")

wrong_binding = json.loads(binding)
wrong_binding["tls_spki_sha256"] = "0" * 64
refused("a binding that does not hash to REPORT_DATA refused",
        lambda: verify(bind=json.dumps(wrong_binding, sort_keys=True, separators=(",", ":"))), "REPORT_DATA")

# The ASK is not the pinned root, so the pin check refuses it before any signature is looked at.
refused("a wrong AMD root refused", lambda: verify(ark_der=read("amd-genoa-ask.der")), "pinned AMD")

print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
