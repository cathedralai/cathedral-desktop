"""Unit tests for manifest parsing and hash checking. No control inputs and no pinned tool needed."""
import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manifest as mf  # noqa: E402

HERE = Path(__file__).resolve().parent
EXAMPLE = HERE.parent / "manifests" / "run5-example.manifest.json"


def good():
    return json.loads(EXAMPLE.read_text())


class Validate(unittest.TestCase):
    def test_example_manifest_is_valid(self):
        mf.load_manifest(EXAMPLE)

    def rejects(self, mutate, text):
        m = good()
        mutate(m)
        with self.assertRaises(mf.ManifestError) as cm:
            mf.validate(m)
        self.assertIn(text, str(cm.exception))

    def test_rejects_bad_schema_number(self):
        self.rejects(lambda m: m.update(schema=2), "schema")

    def test_rejects_missing_input(self):
        self.rejects(lambda m: m["inputs"].pop("initrd"), "inputs")

    def test_rejects_short_hash(self):
        self.rejects(lambda m: m["inputs"]["kernel"].update(sha256="abc"), "sha256")

    def test_rejects_uppercase_hash(self):
        self.rejects(lambda m: m["inputs"]["kernel"].update(sha256="A" * 64), "sha256")

    def test_rejects_path_in_file_name(self):
        self.rejects(lambda m: m["inputs"]["firmware"].update(file="../OVMF.fd"), "bare file name")

    def test_rejects_empty_cmdline(self):
        self.rejects(lambda m: m.update(cmdline=""), "cmdline")

    def test_rejects_missing_cpu_model(self):
        self.rejects(lambda m: m["launch"].pop("vcpu_type"), "vcpu_type")

    def test_rejects_kernel_hashes_off(self):
        self.rejects(lambda m: m["launch"].update(kernel_hashes=False), "kernel_hashes")

    def test_rejects_non_numeric_vcpu_key(self):
        self.rejects(lambda m: m["expected"].update({"two": "0" * 96}), "vCPU count")

    def test_rejects_short_fingerprint(self):
        self.rejects(lambda m: m["expected"].update({"2": "00"}), "96")

    def test_holds_one_fingerprint_per_vcpu_count(self):
        m = good()
        m["expected"]["4"] = "1" * 96
        mf.validate(m)
        self.assertEqual(sorted(m["expected"]), ["2", "4"])

    def test_unreadable_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "bad.json")
            p.write_text("{not json")
            with self.assertRaises(mf.ManifestError):
                mf.load_manifest(p)


class Hashes(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.m = copy.deepcopy(good())
        for name, content in (("firmware", b"fw"), ("kernel", b"kern"), ("initrd", b"rd")):
            f = self.m["inputs"][name]["file"]
            (self.dir / f).write_bytes(content)
            self.m["inputs"][name]["sha256"] = hashlib.sha256(content).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def statuses(self):
        return {n: s for n, s, _ in mf.check_hashes(self.m, self.dir)}

    def test_all_ok(self):
        self.assertEqual(set(self.statuses().values()), {"ok"})

    def test_one_changed_byte_is_a_mismatch(self):
        (self.dir / self.m["inputs"]["kernel"]["file"]).write_bytes(b"kerN")
        s = self.statuses()
        self.assertEqual(s["kernel"], "mismatch")
        self.assertEqual(s["initrd"], "ok")

    def test_missing_file(self):
        (self.dir / self.m["inputs"]["initrd"]["file"]).unlink()
        self.assertEqual(self.statuses()["initrd"], "missing")

    def test_sha256_file_streams_large_input(self):
        p = self.dir / "big"
        data = b"x" * ((1 << 20) * 2 + 5)
        p.write_bytes(data)
        self.assertEqual(mf.sha256_file(p), hashlib.sha256(data).hexdigest())


class Command(unittest.TestCase):
    def test_tool_command_carries_every_measured_input(self):
        cmd = mf.tool_command(good(), "/in", 2)
        for flag in ("--vcpus", "--vcpu-type", "--ovmf", "--kernel", "--initrd", "--append"):
            self.assertIn(flag, cmd)
        self.assertEqual(cmd[cmd.index("--vcpus") + 1], "2")
        self.assertEqual(cmd[cmd.index("--vcpu-type") + 1], "EPYC-v4")
        self.assertEqual(cmd[cmd.index("--append") + 1], good()["cmdline"])

    def test_fingerprint_from_stub_tool_and_failing_tool(self):
        with tempfile.TemporaryDirectory() as d:
            ok = Path(d, "ok.sh")
            ok.write_text("#!/bin/sh\necho " + "ab" * 48 + "\n")
            bad = Path(d, "bad.sh")
            bad.write_text("#!/bin/sh\necho boom >&2\nexit 3\n")
            for p in (ok, bad):
                p.chmod(p.stat().st_mode | stat.S_IXUSR)
            self.assertEqual(mf.compute_fingerprint(good(), d, 2, str(ok)), "ab" * 48)
            with self.assertRaises(mf.ManifestError):
                mf.compute_fingerprint(good(), d, 2, str(bad))

    def test_report_measurement_reads_offset_0x90(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "report.bin")
            p.write_bytes(b"\0" * 0x90 + bytes(range(48)) + b"\xff" * 10)
            self.assertEqual(mf.report_measurement(p), bytes(range(48)).hex())
            short = Path(d, "short.bin")
            short.write_bytes(b"\0" * 10)
            with self.assertRaises(mf.ManifestError):
                mf.report_measurement(short)


if __name__ == "__main__":
    unittest.main()
