#!/usr/bin/env python3
"""Manifest parsing, input hash checks and launch fingerprint computation.

The fingerprint itself comes from the pinned `sev-snp-measure` tool. This file only
reads the manifest, checks the input files against it and builds the tool's command.
Standard library only, so the unit tests run without the pinned virtual environment.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX96 = re.compile(r"^[0-9a-f]{96}$")
INPUT_NAMES = ("firmware", "kernel", "initrd")
REPORT_MEASUREMENT_OFFSET = 0x90  # SNP attestation report, MEASUREMENT field
REPORT_MEASUREMENT_LEN = 48


class ManifestError(Exception):
    pass


def load_manifest(path):
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as e:
        raise ManifestError(f"cannot read manifest {path}: {e}")
    validate(data)
    return data


def validate(m):
    """Reject anything the fingerprint would silently depend on but the manifest omits."""
    if not isinstance(m, dict):
        raise ManifestError("manifest must be a JSON object")
    if m.get("schema") != 1:
        raise ManifestError("schema must be 1")
    tool = m.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "sev-snp-measure" or not isinstance(tool.get("version"), str):
        raise ManifestError("tool must name sev-snp-measure and a version")
    inputs = m.get("inputs")
    if not isinstance(inputs, dict) or set(inputs) != set(INPUT_NAMES):
        raise ManifestError(f"inputs must hold exactly {', '.join(INPUT_NAMES)}")
    for name in INPUT_NAMES:
        entry = inputs[name]
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str) or not entry["file"]:
            raise ManifestError(f"inputs.{name}.file must be a file name")
        f = entry["file"]
        if "/" in f or "\\" in f or f in (".", ".."):
            raise ManifestError(f"inputs.{name}.file must be a bare file name, got {f!r}")
        if not isinstance(entry.get("sha256"), str) or not HEX64.match(entry["sha256"]):
            raise ManifestError(f"inputs.{name}.sha256 must be 64 lowercase hex characters")
    if not isinstance(m.get("cmdline"), str) or not m["cmdline"]:
        raise ManifestError("cmdline must be the exact kernel command line string")
    launch = m.get("launch")
    if not isinstance(launch, dict) or not isinstance(launch.get("vcpu_type"), str) or not launch["vcpu_type"]:
        raise ManifestError("launch.vcpu_type is required (the CPU model changes the measurement)")
    if launch.get("kernel_hashes") is not True:
        raise ManifestError("launch.kernel_hashes must be true (the tool always measures kernel, initrd and command line)")
    expected = m.get("expected")
    if not isinstance(expected, dict) or not expected:
        raise ManifestError("expected must map each vCPU count to a fingerprint")
    for count, fp in expected.items():
        if not re.match(r"^[1-9][0-9]*$", count):
            raise ManifestError(f"expected key {count!r} is not a vCPU count")
        if not isinstance(fp, str) or not HEX96.match(fp):
            raise ManifestError(f"expected[{count}] must be 96 lowercase hex characters")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def check_hashes(m, inputs_dir):
    """Return a list of (name, status, detail); status is ok, mismatch or missing."""
    results = []
    for name in INPUT_NAMES:
        entry = m["inputs"][name]
        p = Path(inputs_dir) / entry["file"]
        if not p.is_file():
            results.append((name, "missing", str(p)))
            continue
        got = sha256_file(p)
        results.append((name, "ok" if got == entry["sha256"] else "mismatch",
                        f"{entry['file']} expected {entry['sha256'][:16]} got {got[:16]}"))
    return results


def tool_command(m, inputs_dir, vcpus, tool_path="sev-snp-measure"):
    d = Path(inputs_dir)
    i = m["inputs"]
    return [tool_path, "--mode", "snp", "--vcpus", str(vcpus), "--vcpu-type", m["launch"]["vcpu_type"],
            "--output-format", "hex", "--ovmf", str(d / i["firmware"]["file"]),
            "--kernel", str(d / i["kernel"]["file"]), "--initrd", str(d / i["initrd"]["file"]),
            "--append", m["cmdline"]]


def compute_fingerprint(m, inputs_dir, vcpus, tool_path="sev-snp-measure"):
    r = subprocess.run(tool_command(m, inputs_dir, vcpus, tool_path), capture_output=True, text=True)
    out = r.stdout.strip()
    if r.returncode != 0 or not HEX96.match(out):
        raise ManifestError(f"{tool_path} failed (exit {r.returncode}): {r.stderr.strip()[-300:]}")
    return out


def tool_version(tool_path="sev-snp-measure"):
    r = subprocess.run([tool_path, "--version"], capture_output=True, text=True)
    return (r.stdout or r.stderr).strip().split()[-1] if r.returncode == 0 else ""


def report_measurement(path):
    b = Path(path).read_bytes()
    end = REPORT_MEASUREMENT_OFFSET + REPORT_MEASUREMENT_LEN
    if len(b) < end:
        raise ManifestError(f"{path} is too short to be an attestation report")
    return b[REPORT_MEASUREMENT_OFFSET:end].hex()


def make_manifest(firmware, kernel, initrd, cmdline, vcpu_type, expected, version, note=""):
    """Build a manifest from real files; used by the control script, not by readers."""
    m = {"schema": 1, "description": note,
         "tool": {"name": "sev-snp-measure", "version": version, "mode": "snp"},
         "inputs": {n: {"file": Path(p).name, "sha256": sha256_file(p)}
                    for n, p in (("firmware", firmware), ("kernel", kernel), ("initrd", initrd))},
         "cmdline": cmdline,
         "launch": {"vcpu_type": vcpu_type, "kernel_hashes": True},
         "expected": expected}
    validate(m)
    return m


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("validate"); s.add_argument("manifest")
    s = sub.add_parser("hashes"); s.add_argument("manifest"); s.add_argument("inputs_dir")
    s = sub.add_parser("fingerprint")
    s.add_argument("manifest"); s.add_argument("inputs_dir"); s.add_argument("--vcpus", type=int, action="append")
    s.add_argument("--tool", default="sev-snp-measure")
    s = sub.add_parser("check"); s.add_argument("manifest"); s.add_argument("inputs_dir"); s.add_argument("--tool", default="sev-snp-measure")
    s = sub.add_parser("report-measurement"); s.add_argument("report")
    s = sub.add_parser("make")
    for a in ("firmware", "kernel", "initrd", "cmdline", "vcpu-type", "vcpus", "expected", "version", "out"):
        s.add_argument("--" + a, required=True)
    s.add_argument("--note", default="")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "validate":
            load_manifest(a.manifest); print("manifest ok")
        elif a.cmd == "hashes":
            bad = 0
            for name, status, detail in check_hashes(load_manifest(a.manifest), a.inputs_dir):
                print(f"{status.upper():8} {name}: {detail}"); bad += status != "ok"
            return 1 if bad else 0
        elif a.cmd == "fingerprint":
            m = load_manifest(a.manifest)
            for n in a.vcpus or [int(k) for k in m["expected"]]:
                print(f"{n} {compute_fingerprint(m, a.inputs_dir, n, a.tool)}")
        elif a.cmd == "check":
            return run_check(a)
        elif a.cmd == "report-measurement":
            print(report_measurement(a.report))
        elif a.cmd == "make":
            m = make_manifest(a.firmware, a.kernel, a.initrd, a.cmdline, a.vcpu_type,
                              {a.vcpus: a.expected}, a.version, a.note)
            Path(a.out).write_text(json.dumps(m, indent=2) + "\n")
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def run_check(a):
    m = load_manifest(a.manifest)
    failed = 0
    want = m["tool"]["version"]
    have = tool_version(a.tool)
    if have != want:
        print(f"FAIL tool version: manifest pins {want}, installed {have or 'none'}")
        failed += 1
    for name, status, detail in check_hashes(m, a.inputs_dir):
        print(f"{'ok  ' if status == 'ok' else 'FAIL'} {name} sha256 {status}: {detail}")
        failed += status != "ok"
    if failed:
        print("RESULT: FAIL (inputs or tool do not match the manifest; fingerprint not computed)")
        return 1
    for count, expected in sorted(m["expected"].items(), key=lambda kv: int(kv[0])):
        got = compute_fingerprint(m, a.inputs_dir, int(count), a.tool)
        same = got == expected
        print(f"{'ok  ' if same else 'FAIL'} fingerprint vcpus={count} expected {expected[:8]}..{expected[-8:]} "
              f"computed {got[:8]}..{got[-8:]}")
        failed += not same
    print("RESULT: PASS" if not failed else "RESULT: FAIL")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
