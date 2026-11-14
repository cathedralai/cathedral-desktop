"""python3 tee/client/test_combined_check.py path/to/boxd
AB#364: the verifier against the real c48 fixtures, boxd's run target over the sealed stream, and
combined_check.py end to end against boxd -dev boxes (with a dev box standing in as the tampered one)."""
import asyncio
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import combined_check  # noqa: E402
import mint_ticket  # noqa: E402
from sealed_stream import Verify, open_stream, verify_snp  # noqa: E402

BOXD = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./boxd")
FIX = os.path.join(HERE, "..", "fixtures")
failures = 0


def check(name, ok, detail=""):
    global failures
    print(f"{'ok  ' if ok else 'FAIL'} {name}  {detail}")
    failures += 0 if ok else 1


def fixture(name, mode="rb"):
    with open(os.path.join(FIX, name), mode) as f:
        return f.read()


def offline():
    import base64
    report, binding = fixture("report.bin"), fixture("binding.json", "r")
    static = base64.b64decode(json.loads(binding)["sealed_stream"]["x25519_public_b64"])
    measurement = report[0x90:0xC0].hex()
    v = Verify(allowed_measurements=[measurement], vcek_der=fixture("vcek.der"),
               tls_spki=combined_check.spki_of(fixture("cert.der")))
    att = verify_snp(report, static, binding, v)
    check("c48 fixture passes chain, binding, TLS key and published MEASUREMENT", att["ok"] and not att["test_mode"],
          measurement[:16])
    for name, ok, detail in combined_check.offline_tamper_checks(report, static, binding, v):
        check(f"offline tamper: {name} refused", ok, detail)
    check("NET line with CIDR gives the address", combined_check.net_address(["NET 10.99.9.13/24 via dhcp"]) == "10.99.9.13")
    check("NET none and the user-mode fallback are not addresses",
          combined_check.net_address(["NET none via x"]) is None
          and combined_check.net_address(["NET 10.0.2.15/24 via fallback"]) is None)


def start_boxd(*flags, tls=28643, stream=28644):
    box = subprocess.Popen([BOXD, "-dev", *flags, "-tls", f"127.0.0.1:{tls}", "-stream", f"127.0.0.1:{stream}"],
                           stderr=subprocess.PIPE, text=True)
    for line in box.stderr:
        if "LISTEN" in line:
            break
    return box


async def run_raw(port, header, payload, ticket="", target="run"):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        s = await open_stream(r, w, target=target, verify=Verify(allow_dev=True), ticket=ticket)
    except RuntimeError as e:
        w.close()
        return {"refused": str(e)}, b""
    await s.send(json.dumps(header).encode())
    for o in range(0, len(payload), 65536):
        await s.send(payload[o:o + 65536])
    head = json.loads(await asyncio.wait_for(s.recv(), 60))
    out = b""
    while "error" not in head and len(out) < head["bytes"]:
        out += await s.recv()
    s.close()
    return head, out


async def run_target():
    box = start_boxd("-noticket")
    try:
        job = b"#!/bin/sh\necho hello from $1; echo to stderr >&2; exit 3\n"
        t0 = time.monotonic()
        head, out = await run_raw(28644, {"size": len(job), "args": ["box"]}, job)
        check("run: exit code and combined output come back", head.get("exit") == 3
              and b"hello from box" in out and b"to stderr" in out, f"{head} {out!r} {(time.monotonic() - t0) * 1000:.0f} ms")
        import hashlib
        check("run: the box reports the sha256 of what it ran", head.get("sha256") == hashlib.sha256(job).hexdigest())

        if os.geteuid() == 0:
            probe = b"#!/bin/sh\nid -u; cat /proc/net/dev\n"
            head, out = await run_raw(28644, {"size": len(probe)}, probe)
            lines = out.decode().split()
            check("run: as root, the job runs as nobody", lines[:1] == ["65534"], lines[:1])
            ifaces = [ln.split(":")[0].strip() for ln in out.decode().splitlines() if ":" in ln]
            check("run: as root, the job has its own network (loopback only)", ifaces == ["lo"], str(ifaces))

        sleeper = b"#!/bin/sh\nsleep 30 &\nsleep 30\n"
        t0 = time.monotonic()
        head, _ = await run_raw(28644, {"size": len(sleeper), "timeout_s": 1}, sleeper)
        took = time.monotonic() - t0
        check("run: timeout kills the job and its children", head.get("timed_out") is True and head.get("exit") == -1
              and took < 10, f"{head} {took:.1f} s")

        head, _ = await run_raw(28644, {"size": 64 << 20 | 1}, b"")
        check("run: oversize upload refused before any bytes", head.get("error") == "size out of range", str(head))
        head, _ = await run_raw(28644, {"size": 4}, b"12345678")
        check("run: more bytes than size refused", head.get("error") == "more bytes than size", str(head))
        head, _ = await run_raw(28644, {"size": 4, "timeout_s": 999}, b"1234")
        check("run: timeout out of range refused", head.get("error") == "timeout out of range", str(head))
    finally:
        box.kill()

    with tempfile.TemporaryDirectory() as tmp:
        key_path = os.path.join(tmp, "ticket.key")
        subprocess.run([sys.executable, os.path.join(HERE, "mint_ticket.py"), "keygen", "--out", key_path],
                       check=True, capture_output=True)
        key = mint_ticket.load_key(key_path)
        box = start_boxd("-ticket-key", os.path.join(tmp, "ticket.pub"), tls=28743, stream=28744)
        try:
            static = await mint_ticket.box_static_key("127.0.0.1", 28744)
            job = b"#!/bin/sh\necho ok\n"
            head, _ = await run_raw(28744, {"size": len(job)}, job,
                                    ticket=mint_ticket.issue(key, box_static=static, target="job"))
            check("run: a ticket for target job does not open run", "refused" in head, str(head))
            head, out = await run_raw(28744, {"size": len(job)}, job,
                                      ticket=mint_ticket.issue(key, box_static=static, target="run"))
            check("run: a ticket for target run opens it", head.get("exit") == 0 and out == b"ok\n", f"{head} {out!r}")
        finally:
            box.kill()


def end_to_end():
    with tempfile.TemporaryDirectory() as tmp:
        job = os.path.join(tmp, "job")
        with open(job, "w") as f:
            f.write("#!/bin/sh\necho hello\nexit 3\n")
        launch = f"exec {BOXD} -dev -noticket -tls 127.0.0.1:{{tls_port}} -stream 127.0.0.1:{{stream_port}}"
        common = ["--launch", launch, "--host", "127.0.0.1", "--tls-port", "29443", "--stream-port", "29444",
                  "--port-stride", "2", "--binary", job, "--expect-exit", "3", "--expect-output", "hello",
                  "--tampered-launch", launch, "--boot-timeout", "10"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "2", "--allow-dev", "--json-out", os.path.join(tmp, "r.json"), *common])
        with open(os.path.join(tmp, "r.json")) as f:
            res = json.load(f)
        boxes = res["boxes"]
        check("e2e dev: two boxes pass every step, the tampered one is refused, exit 0",
              rc == 0 and [b["ok"] for b in boxes] == [True, True, True] and boxes[2]["tampered"]
              and all(set(combined_check.STEPS) <= set(b["ms"]) for b in boxes[:2]),
              out.getvalue().strip().splitlines()[-1])
        check("e2e dev: the tampered box was refused before any job", "refused at" in boxes[2]["detail"]
              and "job" not in boxes[2]["ms"], boxes[2]["detail"])
        print("    " + "\n    ".join(ln for ln in out.getvalue().splitlines() if ln.strip()))

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "1", "--measurement", "ab" * 48, *common])
        check("e2e strict: a box with no SNP report fails the run", rc == 1, out.getvalue().strip().splitlines()[-1])


offline()
asyncio.run(run_target())
end_to_end()
print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
