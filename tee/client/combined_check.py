#!/usr/bin/env python3
"""AB#364: what a customer buys, in one sequence per box, over N boxes.

For each box: boot it, fetch its SEV-SNP report over TLS (8443), check the AMD chain, the key
binding and MEASUREMENT against the published fingerprint, open the sealed stream (8444) to that
same key, then run a real job inside it (upload a static binary, run it, get output and exit code).
Prints per-step times. A tampered box must be refused before any job is sent. One box at a time
(c48 memory is the limit).

    python3 tee/client/combined_check.py --boxes 10 \\
        --launch '/root/snptest/launch-desktop.sh {i}' \\
        --fingerprint-file fingerprint.txt --ticket-key $K \\
        --binary ./hello-static --expect-output hello \\
        --tampered-launch '/root/snptest/launch-desktop.sh tampered' \\
        --json-out run.json

--launch is any shell command that boots one box and writes the box console to stdout (QEMU or
Cloud Hypervisor with the serial console on stdio). {i}, {tls_port} and {stream_port} are filled
in per box. The box address comes from the console NET line, else --host. --box HOST checks a box
that is already up (boot time is then not measured).

Exit 0 only when every box passes every step and every tampered box is refused at the MEASUREMENT check.
A tampered box that fails to boot, answer or serve a report is a failure, not a refusal. A run with
no tampered box, no box booted by --launch, or --allow-dev exits 2 (INCOMPLETE): a smoke check, not
AB#364 evidence.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import queue
import re
import shlex
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from mint_ticket import minter
from sealed_stream import MAX_DATA, Verify, open_stream, verify_snp

STEPS = ["boot", "report", "link", "verify", "job"]
# QEMU user-mode networking hands this out; on a tap box it means DHCP failed.
USER_NET_FALLBACK = "10.0.2.15"


# ---- console of a launched box


class Launched:
    """One box started by --launch; its stdout and stderr are the console."""

    def __init__(self, cmd: str):
        self.t0 = time.monotonic()
        # Own session, so halting kills the hypervisor and not just the shell around it.
        self.proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, errors="replace",
                                     start_new_session=True)
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.console: list[str] = []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(line.rstrip("\n"))
        self.lines.put(None)

    def wait_for(self, prefix: str, deadline: float) -> str:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no {prefix} on the console")
            try:
                line = self.lines.get(timeout=left)
            except queue.Empty:
                continue
            if line is None:
                raise RuntimeError(f"box exited before {prefix} (rc {self.proc.wait()}); last: {self.console[-3:]}")
            self.console.append(line)
            if "BOXD_ERROR" in line or "verity mount failed" in line:
                raise RuntimeError(line.strip())
            if line.lstrip().startswith(prefix):
                return line

    def halt(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.proc.wait()


def net_address(console: list[str]) -> str | None:
    """The box's IP from `NET 10.99.9.13/24 via ...`, or None when it has no usable one."""
    # Only the final `NET <addr> via <script>` line names the address; box-init prints diagnostic NET lines
    # (a DHCP retry, the fallback) before it.
    found = None
    for line in console:
        m = re.match(r"\s*NET\s+(\S+)\s+via\b", line)
        if m:
            found = m.group(1).split("/")[0]
    if found in (None, "none", USER_NET_FALLBACK):
        return None
    return found


# ---- link checks


MAX_REPORT_LINE = 16 << 10  # a report is 1184 bytes, so its hex line is under 2.5 KiB


def fetch_report(host: str, port: int, wait: float = 15.0) -> tuple[bytes | None, bytes]:
    """REPORT over the AB#361 TLS line protocol. The cert is not verified here: the report binds it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode, ctx.minimum_version = False, ssl.CERT_NONE, ssl.TLSVersion.TLSv1_3
    deadline = time.monotonic() + wait
    while True:
        try:
            raw = socket.create_connection((host, port), 5)
            break
        except OSError:
            # LISTEN is printed before the tap side may route; retry briefly.
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)
    with raw, ctx.wrap_socket(raw) as s:
        s.settimeout(10)
        cert = s.getpeercert(binary_form=True)
        s.sendall(b"REPORT\n")
        line = b""
        # One deadline for the whole answer and a size cap: a box that trickles bytes must still fail.
        answer_by = time.monotonic() + 10
        while not line.endswith(b"\n"):
            left = answer_by - time.monotonic()
            if left <= 0:
                raise RuntimeError("box did not finish its REPORT answer in 10 s")
            s.settimeout(left)
            chunk = s.recv(65536)
            if not chunk:
                break
            line += chunk
            if len(line) > MAX_REPORT_LINE:
                raise RuntimeError(f"box REPORT answer longer than {MAX_REPORT_LINE} bytes")
    parts = line.split()
    if parts == [b"NOREPORT"]:
        return None, cert
    if len(parts) != 2 or parts[0] != b"REPORT":
        raise RuntimeError(f"box answered {line[:60]!r}")
    return bytes.fromhex(parts[1].decode()), cert


def spki_of(cert_der: bytes) -> bytes:
    return x509.load_der_x509_certificate(cert_der).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def offline_tamper_checks(report: bytes, static: bytes, binding: str, verify: Verify) -> list[tuple[str, bool, str]]:
    """Feed altered copies of a real, verified report through the same verifier: each must fail."""
    out = []

    def expect_refused(name, rep, stat, bind, v):
        try:
            verify_snp(rep, stat, bind, v)
            out.append((name, False, "accepted"))
        except Exception as e:  # noqa: BLE001 - any refusal is the pass condition
            out.append((name, True, f"{type(e).__name__}: {e}"[:80]))

    flipped = bytearray(report)
    flipped[0x90] ^= 1
    expect_refused("flipped MEASUREMENT byte", bytes(flipped), static, binding, verify)
    wrong_fp = Verify(**{**verify.__dict__, "allowed_measurements": ["00" * 48]})
    expect_refused("wrong published fingerprint", report, static, binding, wrong_fp)
    expect_refused("another stream key", report, bytes(32), binding, verify)
    return out


async def link_and_job(host: str, port: int, verify: Verify, mint, check_link, binary: bytes,
                       args: list[str], timeout_s: int) -> tuple[dict, bytes, dict]:
    """Open the sealed stream to target run (open_stream verifies the box before it sends anything),
    hand the stream to check_link, and only then upload and run one job.

    Returns the result header, the output and the link and job times in ms.
    """
    ms = {}
    t0 = time.monotonic()
    r, w = await asyncio.open_connection(host, port)
    s = await open_stream(r, w, target="run", verify=verify, mint=mint)
    ms["link"] = (time.monotonic() - t0) * 1000
    try:
        t0 = time.monotonic()
        check_link(s)
        ms["verify"] = (time.monotonic() - t0) * 1000
        t0 = time.monotonic()
        await s.send(json.dumps({"size": len(binary), "args": args, "timeout_s": timeout_s}).encode())
        for o in range(0, len(binary), MAX_DATA):
            await s.send(binary[o:o + MAX_DATA])
        head = json.loads(await asyncio.wait_for(s.recv(), timeout_s + 30))
        out = b""
        if "error" not in head:
            while len(out) < head["bytes"]:
                out += await asyncio.wait_for(s.recv(), 30)
        ms["job"] = (time.monotonic() - t0) * 1000
        return head, out, ms
    finally:
        s.close()


# ---- one box


def check_box(name: str, a, verify: Verify, binary: bytes, tampered: bool, launch: str | None = None,
              box_host: str | None = None, index: int = 0) -> dict:
    res = {"box": name, "tampered": tampered, "ms": {}, "ok": False, "detail": ""}
    tls_port = a.tls_port + index * a.port_stride
    stream_port = a.stream_port + index * a.port_stride
    box = None
    step = "boot"
    try:
        host = box_host
        if launch:
            box = Launched(launch.format(i=index, tls_port=tls_port, stream_port=stream_port))
            deadline = box.t0 + a.boot_timeout
            box.wait_for("LISTEN", deadline)
            if a.wait_desktop:
                ready = box.wait_for("DESKTOP ready", deadline)
                res["desktop_uptime"] = ready.split()[-1]
            res["ms"]["boot"] = (time.monotonic() - box.t0) * 1000
            host = net_address(box.console) or a.host
            if not host:
                raise RuntimeError("no usable NET address on the console and no --host")
        res["host"] = host

        step = "report"
        t = time.monotonic()
        report, cert = fetch_report(host, tls_port)
        res["ms"]["report"] = (time.monotonic() - t) * 1000
        if report is None and not (a.allow_dev and not tampered):
            raise RuntimeError("box served no SNP report")
        v = Verify(**{**verify.__dict__, "tls_spki": spki_of(cert)})

        if tampered:
            # A tampered box must not get past the link; nothing is ever uploaded to it.
            step = "verify"
            t = time.monotonic()
            r, w = asyncio.run(_attest_only(host, stream_port))
            try:
                verify_snp(report, r, w, v)
            except ValueError as e:
                res["ms"]["verify"] = (time.monotonic() - t) * 1000
                detail = tampered_refusal(e)
                if detail is None:
                    raise
                res["ok"], res["detail"] = True, detail
                return res
            raise AssertionError("tampered box passed verification")

        step = "link"
        mint = minter(a.ticket_key, "run") if a.ticket_key else None

        def check_link(s):
            # The job goes to the key in the stream's report; it must be the report fetched over TLS.
            nonlocal step
            step = "verify"
            if report is None:
                res["measurement"], step = "DEV", "job"
                return
            if s.report != report:
                raise RuntimeError("stream report differs from the TLS report")
            att = verify_snp(report, s.static, s.binding, v)
            res["measurement"], res["chip"] = att["measurement"], att["chip_id"][:16]
            res["_link"] = (report, s.static, s.binding, v)
            step = "job"

        head, out, ms = asyncio.run(link_and_job(host, stream_port, v, mint, check_link, binary,
                                                 a.arg, a.job_timeout))
        res["ms"].update(ms)
        step = "job"
        if "error" in head:
            raise RuntimeError(f"box refused the job: {head['error']}")
        full = out.decode(errors="replace")
        res["exit"], res["output"] = head["exit"], full[:200]
        if head.get("sha256") != hashlib.sha256(binary).hexdigest():
            raise RuntimeError("box ran a different binary than the one sent")
        if head["exit"] != a.expect_exit:
            raise RuntimeError(f"exit {head['exit']} (want {a.expect_exit}), output {out[:80]!r}")
        if a.expect_output and a.expect_output not in full:
            raise RuntimeError(f"output {out[:80]!r} lacks {a.expect_output!r}")
        res["ok"] = True
    except Exception as e:  # noqa: BLE001 - every failure is reported per box and step
        # For a tampered box too: a box that did not boot, answer or serve a report proves nothing about the verifier.
        res["detail"] = f"{step}: {type(e).__name__}: {e}"[:160]
    finally:
        if box:
            box.halt()
    return res


def tampered_refusal(e: Exception) -> str | None:
    """The negative control passes only when the verifier rejects the box's MEASUREMENT; any other error is a failure."""
    if isinstance(e, ValueError) and "is not an allowed fingerprint" in str(e):
        return f"refused at verify: {e}"[:160]
    return None


async def _attest_only(host: str, port: int) -> tuple[bytes, str]:
    """HELLO and ATTEST only: the box's stream key and binding, without asking for a target."""
    from sealed_stream import b64u_decode, read_frame, write_frame
    r, w = await asyncio.open_connection(host, port)
    try:
        write_frame(w, json.dumps({"v": 1}).encode())
        await w.drain()
        att = json.loads(await read_frame(r))
        if "error" in att or not att.get("report"):
            raise RuntimeError("box presented no attestation report")
        return b64u_decode(att["static"]), att["binding"]
    finally:
        w.close()


# ---- report


def fmt_ms(v):
    return "-" if v is None else f"{v:,.0f}" if v >= 100 else f"{v:.1f}"


def print_table(results: list[dict]):
    print(f"{'box':<12}" + "".join(f"{s + ' ms':>11}" for s in STEPS) + "  result")
    for r in results:
        verdict = ("REFUSED ok" if r["tampered"] else "PASS") if r["ok"] else "FAIL"
        print(f"{r['box']:<12}" + "".join(f"{fmt_ms(r['ms'].get(s)):>11}" for s in STEPS)
              + f"  {verdict}  {r.get('detail') or r.get('output', '').strip()[:40]}")
    good = [r for r in results if not r["tampered"] and r["ok"]]
    for s in STEPS:
        vals = [r["ms"][s] for r in good if s in r["ms"]]
        if vals:
            print(f"  {s:<7} min {fmt_ms(min(vals))}  median {fmt_ms(statistics.median(vals))}  max {fmt_ms(max(vals))} ms  (n={len(vals)})")


def load_fingerprints(a) -> list[str]:
    fps = [m.lower() for m in a.measurement]
    if a.fingerprint_file:
        with open(a.fingerprint_file) as f:
            for line in f:
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    fps.append(line)
    for fp in fps:
        if not re.fullmatch(r"[0-9a-f]{96}", fp):
            raise SystemExit(f"not a 48-byte MEASUREMENT: {fp[:20]}")
    return fps


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_argument_group("boxes")
    src.add_argument("--launch", help="shell command that boots one box, console on stdout")
    src.add_argument("--boxes", type=int, default=10, help="how many boxes to launch (default 10)")
    src.add_argument("--box", action="append", default=[], help="HOST of a box that is already up (repeat)")
    src.add_argument("--tampered-launch", action="append", default=[], help="command booting a tampered box (repeat)")
    src.add_argument("--tampered-box", action="append", default=[], help="HOST of a tampered box that is up (repeat)")
    src.add_argument("--host", help="box address when the console has no usable NET line")
    src.add_argument("--tls-port", type=int, default=8443)
    src.add_argument("--stream-port", type=int, default=8444)
    src.add_argument("--port-stride", type=int, default=0, help="add i*stride to both ports for box i (hostfwd)")
    src.add_argument("--boot-timeout", type=float, default=120)
    src.add_argument("--wait-desktop", action="store_true", help="boot ends at DESKTOP ready, not LISTEN")
    chk = ap.add_argument_group("checks")
    chk.add_argument("--measurement", action="append", default=[], help="published MEASUREMENT hex (repeat)")
    chk.add_argument("--fingerprint-file", help="file of published MEASUREMENT hex lines (AB#363)")
    chk.add_argument("--product", default="Genoa")
    chk.add_argument("--ticket-key", help="Ed25519 mint key; one ticket per box, target run")
    chk.add_argument("--allow-dev", action="store_true", help="accept boxd -dev boxes with no report (local only, never evidence)")
    job = ap.add_argument_group("job")
    job.add_argument("--binary", required=True, help="static binary to upload and run")
    job.add_argument("--arg", action="append", default=[], help="argument for the binary (repeat)")
    job.add_argument("--expect-exit", type=int, default=0)
    job.add_argument("--expect-output", help="substring the output must contain")
    job.add_argument("--job-timeout", type=int, default=30)
    ap.add_argument("--json-out")
    a = ap.parse_args(argv)

    fps = load_fingerprints(a)
    if not fps and not a.allow_dev:
        # An empty list would let verify_snp pass any MEASUREMENT.
        ap.error("pin the published fingerprint: --measurement or --fingerprint-file")
    if not a.launch and not a.box:
        ap.error("--launch or --box")
    if a.launch and a.boxes < 1:
        ap.error("--boxes must be at least 1")
    if a.allow_dev:
        print("DEV MODE: boxes without an SNP report are accepted. Not evidence for AB#364.")
    with open(a.binary, "rb") as f:
        binary = f.read()
    verify = Verify(product=a.product, allowed_measurements=fps, allow_dev=a.allow_dev)

    plan: list[tuple[str, bool, str | None, str | None, int]] = []
    if a.launch:
        plan += [(f"box{i + 1}", False, a.launch, None, i) for i in range(a.boxes)]
    plan += [(h, False, None, h, i) for i, h in enumerate(a.box, start=len(plan))]
    plan += [(f"tampered{i + 1}", True, cmd, None, len(plan) + i) for i, cmd in enumerate(a.tampered_launch)]
    plan += [(f"tampered:{h}", True, None, h, len(plan) + i) for i, h in enumerate(a.tampered_box)]

    results = []
    for name, tampered, launch, host, index in plan:
        r = check_box(name, a, verify, binary, tampered, launch=launch, box_host=host, index=index)
        print(f"{name}: {'ok' if r['ok'] else 'FAIL'} {r['detail']}", flush=True)
        results.append(r)

    offline = []
    link = next((r.pop("_link") for r in results if "_link" in r), None)
    for r in results:
        r.pop("_link", None)
    if link:
        offline = offline_tamper_checks(*link)
    print()
    print_table(results)
    for name, ok, detail in offline:
        print(f"{'ok  ' if ok else 'FAIL'} offline tamper: {name} refused  {detail}")

    passed = all(r["ok"] for r in results) and all(ok for _, ok, _ in offline)
    good = sum(1 for r in results if r["ok"] and not r["tampered"])
    refused = sum(1 for r in results if r["ok"] and r["tampered"])
    # Evidence needs a tampered box refused, at least one box booted here and timed, and real SNP reports.
    # Anything less is a smoke run: no tampered box shows nothing about refusal, --box measures no boot,
    # and --allow-dev accepts boxes with no report.
    missing = [why for why, bad in (("no tampered box", not any(r["tampered"] for r in results)),
                                    ("no box booted by --launch", not any("boot" in r["ms"] for r in results
                                                                         if not r["tampered"])),
                                    ("--allow-dev", a.allow_dev)) if bad]
    complete = not missing
    verdict = ("ALL CHECKS PASSED" if complete else f"INCOMPLETE ({', '.join(missing)})") if passed else "FAILED"
    print(f"\n{verdict}: {good}/{sum(not r['tampered'] for r in results)} boxes "
          f"passed, {refused}/{sum(r['tampered'] for r in results)} tampered refused, fingerprint "
          f"{fps[0][:16] + '...' if fps else 'none (dev)'}")
    if a.json_out:
        with open(a.json_out, "w") as f:
            json.dump({"fingerprints": fps, "boxes": results,
                       "offline_tamper": [{"check": n, "refused": ok, "detail": d} for n, ok, d in offline],
                       "passed": passed, "complete": complete,
                       "launch": a.launch and shlex.split(a.launch)[0]}, f, indent=2)
    if not passed:
        return 1
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
