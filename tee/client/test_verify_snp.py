"""python3 tee/client/test_verify_snp.py
The Python verifier against the saved chip report in tee/fixtures: accepted as it is, accepted with
its own fingerprint pinned, refused with another fingerprint, refused when any signed byte, the
binding or the AMD root is wrong. No network and no box: the VCEK is the saved one."""
import base64
import hashlib
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
refused("one flipped fingerprint bit refused, and the message names the report signature", lambda: verify(bytes(flipped), ark_der=read("amd-genoa-ark.der")), "report signature does not verify with the VCEK")

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

# ---- each signature check names itself (cdp_shim prints only str(e), and a bare InvalidSignature prints nothing).
# Same wording as tee/web/snp-verify.js.
import sealed_stream as ss  # noqa: E402  (module import so a missing name fails its own check)

ASK = read("amd-genoa-ask.der")


def flip_last(b):
    b = bytearray(b)
    b[-1] ^= 1
    return bytes(b)


def verify_with(ask_der=ASK, vcek_der=None, ark_der=ARK, rep=report):
    v = Verify(ark_der=ark_der, ask_der=ask_der, vcek_der=vcek_der or read("vcek.der"), allow_any_measurement=True)
    return verify_snp(rep, static_pub, binding, v)


refused("tampered ASK: names the ASK check", lambda: verify_with(ask_der=flip_last(ASK)), "ASK is not signed by the ARK")
refused("tampered VCEK: names the VCEK check", lambda: verify_with(vcek_der=flip_last(read("vcek.der"))), "VCEK is not signed by the ASK")
tampered_ark = flip_last(ARK)
saved_pin = dict(ss.AMD_ARK_SHA256)
ss.AMD_ARK_SHA256["Genoa"] = hashlib.sha256(tampered_ark).hexdigest()  # let the pin pass so the self-signature is what fails
try:
    refused("tampered ARK (pin matched): names the ARK self-signature check", lambda: verify_with(ark_der=tampered_ark), "ARK self-signature failed")
finally:
    ss.AMD_ARK_SHA256.clear()
    ss.AMD_ARK_SHA256.update(saved_pin)
sig_errors = set()
for label, fn in (("ASK", lambda: verify_with(ask_der=flip_last(ASK))), ("VCEK", lambda: verify_with(vcek_der=flip_last(read("vcek.der")))),
                  ("report", lambda: verify_with(rep=bytes(flipped)))):
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        sig_errors.add(str(e))
check("the three failures give three different, non-empty messages", len(sig_errors) == 3 and "" not in sig_errors, str(sig_errors))

# ---- customer mode (AB#353 WP2): HOST_DATA must equal sha256("cathedral-tee-customer/v1\0" || customer key).


with open(os.path.join(FX, "..", "testdata", "customer_host_data_v1.json")) as f:
    vec = json.load(f)
k_pub = bytes.fromhex(vec["customer"]["public_key_hex"])
KEY = vec["customer"]["public_key_b64u"]
GOOD = bytes.fromhex(vec["customer"]["host_data_hex"])
LISTED = {"allowed_measurements": [measurement]}

nz = vec["without_trailing_zero"]
try:
    check("vector: preimage is domain, zero byte, key", vec["customer"]["preimage_hex"] == vec["domain_hex"] + vec["customer"]["public_key_hex"] and vec["domain_hex"].endswith("00"))
    check("vector: Python rebuilds HOST_DATA from the key", ss.customer_host_data(k_pub).hex() == vec["customer"]["host_data_hex"])
    check("vector: file value is sha256 of the stored preimage", hashlib.sha256(bytes.fromhex(vec["customer"]["preimage_hex"])).hexdigest() == vec["customer"]["host_data_hex"])
    check("vector: a different key gives the other stored value", ss.customer_host_data(bytes.fromhex(vec["other_customer"]["public_key_hex"])).hex() == vec["other_customer"]["host_data_hex"])
    check("vector: the domain without its trailing zero byte gives a different value",
          nz["host_data_hex"] != vec["customer"]["host_data_hex"] and hashlib.sha256(bytes.fromhex(nz["preimage_hex"])).hexdigest() == nz["host_data_hex"])
    check("vector: the stored unlabelled sha256(key) differs and is what sha256 of the bare key gives",
          vec["unlabelled_sha256_of_key"]["host_data_hex"] != vec["customer"]["host_data_hex"] and hashlib.sha256(k_pub).hexdigest() == vec["unlabelled_sha256_of_key"]["host_data_hex"])
    check("vector: the stored b64url form decodes to the stored key", ss.parse_customer_key(KEY) == k_pub)
except Exception as e:  # noqa: BLE001
    check("vector", False, f"{type(e).__name__}: {e}")


# The pure check: check_customer_host_data(host_data bytes, customer public key bytes). A check that only tests "not zero" fails these.
def chk(hd, pub=k_pub):
    return ss.check_customer_host_data(hd, pub)


try:
    chk(GOOD)
    check("check: HOST_DATA for this key is accepted", True)
except Exception as e:  # noqa: BLE001
    check("check: HOST_DATA for this key is accepted", False, f"{type(e).__name__}: {e}")
refused("check: HOST_DATA for a different customer key is refused", lambda: chk(bytes.fromhex(vec["other_customer"]["host_data_hex"])), "HOST_DATA does not match")
refused("check: all-zero HOST_DATA is refused as zero", lambda: chk(bytes(32)), "HOST_DATA is zero")
refused("check: sha256(key) without the label is refused", lambda: chk(bytes.fromhex(vec["unlabelled_sha256_of_key"]["host_data_hex"])), "HOST_DATA does not match")
refused("check: the value built without the trailing zero byte is refused", lambda: chk(bytes.fromhex(nz["host_data_hex"])), "HOST_DATA does not match")
refused("check: a 31-byte HOST_DATA is refused", lambda: chk(GOOD[:31]), "HOST_DATA")
refused("check: a 33-byte HOST_DATA is refused", lambda: chk(GOOD + b"\0"), "HOST_DATA")
refused("check: a 31-byte customer key is a usage error", lambda: chk(GOOD, k_pub[:31]), "invalid customer key")
all_flips = True
for i in range(32):
    for bit in (0x01, 0x80):
        h = bytearray(GOOD)
        h[i] ^= bit
        try:
            chk(bytes(h))
            all_flips = False
        except Exception:  # noqa: BLE001
            pass
check("check: comparison is exact, a one-bit change in any of the 32 bytes is refused", all_flips)

check("saved report HOST_DATA is all zero (today's fixture)", report[0xC0:0xE0] == bytes(32))
refused("customer key set, HOST_DATA zero: refused, names HOST_DATA and zero",
        lambda: verify(ark_der=ARK, customer_key=KEY, **LISTED), "HOST_DATA is zero")
edited = bytearray(report)
edited[0xC0:0xE0] = GOOD
refused("customer key set, right HOST_DATA in an unsigned edit: the signature check still refuses",
        lambda: verify(bytes(edited), ark_der=ARK, customer_key=KEY, **LISTED), "report signature does not verify")
refused("customer key set, a wrong measurement is refused before HOST_DATA is looked at",
        lambda: verify(ark_der=ARK, allowed_measurements=["ff" * 48], customer_key=KEY), "not an allowed fingerprint")

# Customer mode refuses every waiver: the host picks HOST_DATA freely, so it binds the key only with the build checked too.
refused("customer key set + allow_any_measurement: refused by name", lambda: Verify(customer_key=KEY, allow_any_measurement=True, **LISTED), "customer mode")
refused("customer key set + allow_any_measurement: the message names the waiver", lambda: Verify(customer_key=KEY, allow_any_measurement=True, **LISTED), "allow_any_measurement")
refused("customer key set + empty fingerprint list: refused by name", lambda: Verify(customer_key=KEY, allowed_measurements=[]), "customer mode needs a fingerprint list")
refused("customer key set + allow_dev: refused by name", lambda: Verify(customer_key=KEY, allow_dev=True, **LISTED), "customer mode refuses allow_dev")
for label, setter in (("allow_any_measurement", lambda v: setattr(v, "allow_any_measurement", True)), ("allow_dev", lambda v: setattr(v, "allow_dev", True)),
                      ("an emptied list", lambda v: setattr(v, "allowed_measurements", []))):
    def after_build(setter=setter):
        vv = Verify(customer_key=KEY, **LISTED)
        setter(vv)
        return verify_snp(report, static_pub, binding, vv)

    refused(f"waiver set after the options were built ({label}): verify_snp still refuses", after_build, "customer mode")

b64u = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
for label, bad in (("empty string", ""), ("not base64url", "!" * 43), ("standard base64 characters", KEY.replace("-", "+").replace("_", "/") + "/"),
                   ("padded", KEY + "="), ("31 bytes", b64u(k_pub[:31])), ("33 bytes", b64u(k_pub + b"\0")), ("a number", 5),
                   ("raw bytes", k_pub), ("non-canonical trailing bits", KEY[:42] + "B")):
    # Usage error when the options are built, and again if the field is set afterwards and the verifier is called.
    refused(f"customer key {label}: usage error when the options are built", lambda bad=bad: Verify(customer_key=bad, **LISTED), "invalid customer key")
    def set_after(bad=bad):
        vv = Verify(**LISTED)
        vv.customer_key = bad
        return verify_snp(report, static_pub, binding, vv)

    refused(f"customer key {label}: usage error from the verifier too", set_after, "invalid customer key")

# Off by default: customer_key None is the only way to leave it off, and the result is what main returns.
off = verify(ark_der=ARK, allow_any_measurement=True)
check("no customer key: same result as before, including fixtures with zero HOST_DATA and the waiver",
      off["ok"] and set(off) == {"ok", "test_mode", "measurement", "chip_id", "version"}, str(sorted(off)))
check("Verify has no customer key by default", getattr(Verify(), "customer_key", "missing") is None)
check("no customer key: allow_dev and allow_any_measurement still build as on main", Verify(allow_dev=True, allow_any_measurement=True).allow_dev)

# ---- review fixes (AB#353): weak customer keys, ticket under the customer key, HOST_DATA offset.
weak = vec["weak_keys"]["small_order_hex"] + vec["weak_keys"]["non_canonical_hex"]
check("vector: 8 small-order encodings are listed", len(vec["weak_keys"]["small_order_hex"]) == 8)
for h in weak:
    wk = b64u(bytes.fromhex(h))
    refused(f"weak customer key {h[:8]}..{h[-4:]}: usage error", lambda wk=wk: ss.parse_customer_key(wk), "invalid customer key")
    refused(f"weak customer key {h[:8]}..{h[-4:]}: Verify refuses it when built", lambda wk=wk: Verify(customer_key=wk, **LISTED), "invalid customer key")
    refused(f"weak customer key {h[:8]}..{h[-4:]}: the pure check refuses it", lambda h=h: ss.check_customer_host_data(GOOD, bytes.fromhex(h)), "invalid customer key")
try:
    ss.parse_customer_key(KEY)
    check("a real customer key is still accepted", True)
except Exception as e:  # noqa: BLE001
    check("a real customer key is still accepted", False, f"{type(e).__name__}: {e}")

# HOST_DATA is bytes 0xC0 to 0xDF. A synthetic buffer whose neighbours differ, so a wrong offset cannot pass.
buf = bytearray(0x2A0 + 144)
buf[0xA0:0xC0] = b"\x11" * 32
buf[0xC0:0xE0] = b"\x22" * 32
buf[0xE0:0x100] = b"\x33" * 32
try:
    check("report_host_data reads bytes 0xC0 to 0xDF", ss.report_host_data(bytes(buf)) == b"\x22" * 32)
except Exception as e:  # noqa: BLE001
    check("report_host_data reads bytes 0xC0 to 0xDF", False, f"{type(e).__name__}: {e}")

# The ticket the client sends in customer mode: present, and signed by the customer key.
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives import serialization as _ser  # noqa: E402

ck, ok_ = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
raw_pub = ck.public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)


def mk(priv, body=b'{"box":"x","target":"vnc"}'):
    return f"{b64u(body)}.{b64u(priv.sign(body))}"


try:
    ss.check_customer_ticket(mk(ck), raw_pub)
    check("ticket signed by the customer key is accepted", True)
except Exception as e:  # noqa: BLE001
    check("ticket signed by the customer key is accepted", False, f"{type(e).__name__}: {e}")
refused("empty ticket in customer mode: refused by name", lambda: ss.check_customer_ticket("", raw_pub), "customer mode needs a ticket")
refused("ticket signed by another key: usage error", lambda: ss.check_customer_ticket(mk(ok_), raw_pub), "signed by the customer key")
good_t = mk(ck)
refused("ticket with a changed body: refused", lambda: ss.check_customer_ticket(b64u(b'{"box":"y"}') + "." + good_t.split(".")[1], raw_pub), "signed by the customer key")
for bad in ("abc", "a.b.c", "!!.??", "AAAA.AAAA"):
    refused(f"malformed ticket {bad!r}: refused", lambda bad=bad: ss.check_customer_ticket(bad, raw_pub), "customer mode")

# Message 2 must carry the marker; only then may a stream be called bound to the customer's key.
try:
    ss.check_ready({"ok": True, "mode": "customer"}, KEY)
    check("message 2 with mode customer and a customer key: accepted", True)
except Exception as e:  # noqa: BLE001
    check("message 2 with mode customer and a customer key: accepted", False, f"{type(e).__name__}: {e}")
for label, ready in (("no marker", {"ok": True}), ("another mode", {"ok": True, "mode": "cathedral"}), ("a non-string mode", {"ok": True, "mode": ["customer"]})):
    refused(f"customer key, message 2 with {label}: refused with a named reason", lambda ready=ready: ss.check_ready(ready, KEY), "did not confirm customer mode")
try:
    ss.check_ready({"ok": True}, None)
    ss.check_ready({"ok": True, "mode": "customer"}, None)
    check("no customer key: message 2 is accepted with or without the member", True)
except Exception as e:  # noqa: BLE001
    check("no customer key: message 2 is accepted with or without the member", False, f"{type(e).__name__}: {e}")
check("the verifier result no longer claims a binding by itself", "customer_bound" not in verify(ark_der=ARK, allow_any_measurement=True))

print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
