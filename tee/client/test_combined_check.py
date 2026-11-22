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
    wrong = Verify(**{**v.__dict__, "allowed_measurements": ["00" * 48]})
    try:
        verify_snp(report, static, binding, wrong)
        check("tampered refusal: the c48 report under another fingerprint is refused", False, "accepted")
    except ValueError as e:
        check("tampered refusal: a MEASUREMENT rejection from the verifier counts as the refusal",
              combined_check.tampered_refusal(e) is not None, str(e)[:60])
    check("tampered refusal: other errors do not count",
          combined_check.tampered_refusal(ValueError("report too short")) is None
          and combined_check.tampered_refusal(RuntimeError("box presented no attestation report")) is None
          and combined_check.tampered_refusal(ConnectionRefusedError()) is None)
    check("NET line with CIDR gives the address", combined_check.net_address(["NET 10.99.9.13/24 via dhcp"]) == "10.99.9.13")
    check("NET: a diagnostic line before the final one is skipped",
          combined_check.net_address(["NET /sbin/x configured nothing, retrying with /sbin/box-dhcp",
                                      "NET 10.99.9.13/24 via /sbin/box-dhcp"]) == "10.99.9.13")
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


def static_job(body):
    """Match the upload contract: no shell or dynamic loader from the desktop filesystem."""
    with tempfile.TemporaryDirectory() as tmp:
        src, binary = os.path.join(tmp, "job.c"), os.path.join(tmp, "job")
        with open(src, "w") as f:
            f.write("#include <stdio.h>\n#include <unistd.h>\n#include <stdlib.h>\n"
                    "#include <sys/stat.h>\nint main(int argc, char **argv) {" + body + "}")
        subprocess.run(["cc", "-static", "-O2", "-o", binary, src], check=True, capture_output=True)
        with open(binary, "rb") as f:
            return f.read()


async def run_target():
    box = start_boxd("-noticket")
    try:
        job = static_job('printf("hello from %s\\n", argv[1]); fprintf(stderr,"to stderr\\n"); return 3;')
        t0 = time.monotonic()
        head, out = await run_raw(28644, {"size": len(job), "args": ["box"]}, job)
        check("run: exit code and combined output come back", head.get("exit") == 3
              and b"hello from box" in out and b"to stderr" in out, f"{head} {out!r} {(time.monotonic() - t0) * 1000:.0f} ms")
        import hashlib
        check("run: the box reports the sha256 of what it ran", head.get("sha256") == hashlib.sha256(job).hexdigest())

        if os.geteuid() == 0:
            probe = static_job('struct stat st; printf("%d\\n",getuid()); printf("proc_hidden=%d\\n",stat("/proc", &st)!=0); return 0;')
            head, out = await run_raw(28644, {"size": len(probe)}, probe)
            lines = out.decode().split()
            check("run: as root, the job runs as nobody", lines[:1] == ["65534"], lines[:1])
            check("run: job cannot see host procfs", "proc_hidden=1" in lines, str(lines))

        sleeper = static_job('if (fork()==0) {sleep(30); return 0;} sleep(30); return 0;')
        t0 = time.monotonic()
        head, _ = await run_raw(28644, {"size": len(sleeper), "timeout_s": 1}, sleeper)
        took = time.monotonic() - t0
        check("run: timeout kills the job and its children", head.get("timed_out") is True and head.get("exit") == -1
              and took < 10, f"{head} {took:.1f} s")

        # A client that hangs up mid-job frees the box: the next job is not answered "busy".
        r, w = await asyncio.open_connection("127.0.0.1", 28644)
        s = await open_stream(r, w, target="run", verify=Verify(allow_dev=True))
        long_job = static_job('sleep(120); return 0;')
        await s.send(json.dumps({"size": len(long_job), "timeout_s": 300}).encode())
        await s.send(long_job)
        await asyncio.sleep(0.5)
        s.close()
        t0 = time.monotonic()
        quick = static_job('puts("again"); return 0;')
        while True:
            try:
                head, out = await run_raw(28644, {"size": len(quick)}, quick)
            except ConnectionResetError:
                # A busy refusal can close the stream while run_raw is still writing.
                # The disconnect must still free the box within the same deadline.
                if time.monotonic() - t0 > 10:
                    raise
                await asyncio.sleep(0.2)
                continue
            if head.get("error") != "busy" or time.monotonic() - t0 > 10:
                break
            await asyncio.sleep(0.2)
        check("run: a client that hangs up stops its job and frees the box", head.get("exit") == 0 and out == b"again\n",
              f"{head} after {time.monotonic() - t0:.1f} s")

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
            job = static_job('puts("ok"); return 0;')
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
        with open(job, "wb") as f:
            f.write(static_job('printf("%0300d\\nhello\\n",0); return 3;'))
        launch = f"exec {BOXD} -dev -noticket -tls 127.0.0.1:{{tls_port}} -stream 127.0.0.1:{{stream_port}}"
        common = ["--launch", launch, "--host", "127.0.0.1", "--tls-port", "29443", "--stream-port", "29444",
                  "--port-stride", "2", "--binary", job, "--expect-exit", "3", "--expect-output", "hello",
                  "--boot-timeout", "10"]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "2", "--allow-dev", "--json-out", os.path.join(tmp, "r.json"), *common])
        with open(os.path.join(tmp, "r.json")) as f:
            res = json.load(f)
        boxes = res["boxes"]
        last = out.getvalue().strip().splitlines()[-1]
        check("e2e dev: two boxes pass every step; a dev run with no tampered box is INCOMPLETE, exit 2",
              rc == 2 and [b["ok"] for b in boxes] == [True, True] and res["complete"] is False
              and last.startswith("INCOMPLETE (no tampered box") and "--allow-dev" in last and all(set(combined_check.STEPS) <= set(b["ms"]) for b in boxes),
              last)
        print("    " + "\n    ".join(ln for ln in out.getvalue().splitlines() if ln.strip()))

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "1", "--allow-dev", "--json-out", os.path.join(tmp, "r.json"),
                                      *common, "--tampered-launch", launch])
        with open(os.path.join(tmp, "r.json")) as f:
            boxes = json.load(f)["boxes"]
        check("e2e dev: a tampered box with no report is a failure, not a refusal, exit 1",
              rc == 1 and boxes[1]["tampered"] and not boxes[1]["ok"] and boxes[1]["detail"].startswith("report:")
              and "job" not in boxes[1]["ms"], boxes[1]["detail"])

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "1", "--allow-dev", "--json-out", os.path.join(tmp, "r.json"),
                                      *common, "--tampered-launch", "exit 1"])
        with open(os.path.join(tmp, "r.json")) as f:
            boxes = json.load(f)["boxes"]
        check("e2e dev: a tampered box that never boots is a failure, exit 1",
              rc == 1 and not boxes[1]["ok"] and boxes[1]["detail"].startswith("boot:"), boxes[1]["detail"])

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "1", "--allow-dev", "--json-out", os.path.join(tmp, "r.json"),
                                      *common, "--tampered-box", "127.0.0.1", "--tls-port", "29943",
                                      "--stream-port", "29944"])
        with open(os.path.join(tmp, "r.json")) as f:
            boxes = json.load(f)["boxes"]
        check("e2e dev: an unreachable tampered box is a failure, exit 1",
              rc == 1 and boxes[-1]["tampered"] and not boxes[-1]["ok"], boxes[-1]["detail"])

        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                combined_check.main(["--boxes", "0", "--measurement", "ab" * 48, *common])
            check("--boxes 0 is refused", False, "accepted")
        except SystemExit as e:
            check("--boxes 0 is refused", e.code == 2, str(e.code))

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = combined_check.main(["--boxes", "1", "--measurement", "ab" * 48, *common])
        check("e2e strict: a box with no SNP report fails the run", rc == 1, out.getvalue().strip().splitlines()[-1])


offline()
asyncio.run(run_target())
end_to_end()
print("all checks passed" if not failures else f"{failures} failure(s)")
sys.exit(1 if failures else 0)
