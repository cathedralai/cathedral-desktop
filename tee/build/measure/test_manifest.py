"""Unit tests for manifest parsing and hash checking. No control inputs and no pinned tool needed."""
import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import manifest as mf  # noqa: E402

HERE = Path(__file__).resolve().parent
EXAMPLE = HERE.parent / "manifests" / "run5-example.manifest.json"


FIXTURES = HERE.parent.parent / "fixtures"
REQUIREMENTS = HERE / "requirements.txt"


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


class LaunchParameters(unittest.TestCase):
    """Every input that changes the number is recorded and passed explicitly, never left to the tool's default."""

    def rejects(self, mutate, text):
        m = good()
        mutate(m)
        with self.assertRaises(mf.ManifestError) as cm:
            mf.validate(m)
        self.assertIn(text, str(cm.exception))

    def test_example_records_both(self):
        self.assertEqual(good()["launch"]["guest_features"], "0x1")
        self.assertEqual(good()["launch"]["vmm_type"], "QEMU")

    def test_guest_features_is_required(self):
        self.rejects(lambda m: m["launch"].pop("guest_features"), "guest_features")

    def test_vmm_type_is_required(self):
        self.rejects(lambda m: m["launch"].pop("vmm_type"), "vmm_type")

    def test_guest_features_must_be_hex(self):
        self.rejects(lambda m: m["launch"].update(guest_features="1"), "guest_features")
        self.rejects(lambda m: m["launch"].update(guest_features="0x"), "guest_features")

    def test_unknown_vmm_type_is_refused(self):
        self.rejects(lambda m: m["launch"].update(vmm_type="XEN"), "vmm_type")

    def test_command_passes_both_explicitly(self):
        cmd = mf.tool_command(good(), "/in", 2)
        self.assertEqual(cmd[cmd.index("--guest-features") + 1], "0x1")
        self.assertEqual(cmd[cmd.index("--vmm-type") + 1], "QEMU")

    def test_another_value_reaches_the_tool_and_changes_the_number(self):
        with tempfile.TemporaryDirectory() as d:
            tool = fake_tool(d)
            base = mf.compute_fingerprint(good(), d, 2, tool)
            m = good()
            m["launch"]["guest_features"] = "0x3"
            self.assertNotEqual(mf.compute_fingerprint(m, d, 2, tool), base)
            m = good()
            m["launch"]["vmm_type"] = "ec2"
            self.assertNotEqual(mf.compute_fingerprint(m, d, 2, tool), base)


class FullMatch(unittest.TestCase):
    def rejects(self, mutate):
        m = good()
        mutate(m)
        with self.assertRaises(mf.ManifestError):
            mf.validate(m)

    def test_input_hash_with_trailing_newline_is_refused(self):
        self.rejects(lambda m: m["inputs"]["kernel"].update(sha256=m["inputs"]["kernel"]["sha256"] + "\n"))

    def test_fingerprint_with_trailing_newline_is_refused(self):
        self.rejects(lambda m: m.update(expected={"2": "0" * 96 + "\n"}))

    def test_vcpu_count_with_trailing_newline_is_refused(self):
        self.rejects(lambda m: m.update(expected={"2\n": "0" * 96}))

    def test_tool_output_with_trailing_junk_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "junk.sh")
            p.write_text("#!/bin/sh\necho " + "ab" * 48 + " extra\n")
            p.chmod(p.stat().st_mode | stat.S_IXUSR)
            with self.assertRaises(mf.ManifestError):
                mf.compute_fingerprint(good(), d, 2, str(p))


class ToolVersion(unittest.TestCase):
    def test_empty_version_is_refused(self):
        m = good()
        m["tool"]["version"] = ""
        with self.assertRaises(mf.ManifestError) as cm:
            mf.validate(m)
        self.assertIn("tool.version", str(cm.exception))

    def test_pinned_version_is_read_from_requirements(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "requirements.txt")
            p.write_text("# c\nfoo==1.0 \\\n    --hash=sha256:" + "0" * 64 + "\nsev-snp-measure==9.8.7 \\\n    --hash=sha256:" + "1" * 64 + "\n")
            self.assertEqual(mf.pinned_version(p), "9.8.7")
            p.write_text("foo==1.0\n")
            with self.assertRaises(mf.ManifestError):
                mf.pinned_version(p)

    def test_example_manifest_pins_the_version_in_requirements(self):
        self.assertEqual(good()["tool"]["version"], mf.pinned_version(REQUIREMENTS))


class HashList(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        (self.dir / "sub").mkdir()
        (self.dir / "a.bin").write_bytes(b"aaa")
        (self.dir / "sub" / "b.bin").write_bytes(b"bbb")
        self.list = self.dir / "list.sha256"
        self.list.write_text("".join(f"{mf.sha256_file(self.dir / r)}  {r}\n" for r in ("a.bin", "sub/b.bin")))

    def tearDown(self):
        self.tmp.cleanup()

    def test_matching_bundle_passes(self):
        self.assertEqual(mf.verify_hash_list(self.list, self.dir), [])

    def test_changed_byte_is_reported(self):
        (self.dir / "sub" / "b.bin").write_bytes(b"bbc")
        self.assertEqual([(r, s) for r, s in mf.verify_hash_list(self.list, self.dir)], [("sub/b.bin", "mismatch")])

    def test_missing_file_is_reported(self):
        (self.dir / "a.bin").unlink()
        self.assertEqual([(r, s) for r, s in mf.verify_hash_list(self.list, self.dir)], [("a.bin", "missing")])

    def test_escaping_path_is_refused(self):
        self.list.write_text(f"{'0' * 64}  ../x\n")
        with self.assertRaises(mf.ManifestError):
            mf.verify_hash_list(self.list, self.dir)

    def test_committed_list_is_well_formed(self):
        text = (HERE / "control-inputs.sha256").read_text().splitlines()
        self.assertGreaterEqual(len(text), 18)
        for line in text:
            self.assertRegex(line, r"^[0-9a-f]{64}  [A-Za-z0-9._/-]+$")


@unittest.skipUnless(shutil.which("node") or os.environ.get("REQUIRE_NODE"),
                     "node is not installed (CI sets REQUIRE_NODE=1 so this cannot be skipped there)")
class ReportSignature(unittest.TestCase):
    """The control only counts a report's MEASUREMENT after the repository's verifier checks its signature."""

    def verify(self, report_bytes):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "report.bin")
            p.write_bytes(report_bytes)
            return mf.verified_report(p, FIXTURES / "vcek.der")

    def real(self):
        return (FIXTURES / "report.bin").read_bytes()

    def test_real_report_verifies_and_gives_measurement_and_policy(self):
        r = self.verify(self.real())
        self.assertEqual(r["measurement"], mf.report_measurement(FIXTURES / "report.bin"))
        self.assertEqual(r["policy"], "0000000000030000")

    def test_flipped_signature_byte_does_not_count(self):
        b = bytearray(self.real())
        b[0x2A0 + 5] ^= 0x01
        with self.assertRaises(mf.ManifestError) as cm:
            self.verify(bytes(b))
        self.assertIn("signature", str(cm.exception))

    def test_flipped_measurement_byte_does_not_count(self):
        b = bytearray(self.real())
        b[0x90] ^= 0x01
        with self.assertRaises(mf.ManifestError):
            self.verify(bytes(b))

    def test_truncated_report_does_not_count(self):
        with self.assertRaises(mf.ManifestError):
            self.verify(self.real()[:0x2A0])

    def test_unreadable_vcek_does_not_count(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "report.bin")
            p.write_bytes(self.real())
            with self.assertRaises(mf.ManifestError):
                mf.verified_report(p, Path(d, "missing.der"))


class Strict(unittest.TestCase):
    def rejects(self, mutate, text):
        m = good()
        mutate(m)
        with self.assertRaises(mf.ManifestError) as cm:
            mf.validate(m)
        self.assertIn(text, str(cm.exception))

    def test_rejects_missing_mode(self):
        self.rejects(lambda m: m["tool"].pop("mode"), "tool.mode")

    def test_rejects_mode_sev(self):
        self.rejects(lambda m: m["tool"].update(mode="sev"), "tool.mode")

    def test_rejects_mode_seves(self):
        self.rejects(lambda m: m["tool"].update(mode="seves"), "tool.mode")

    def test_rejects_unknown_top_level_key(self):
        self.rejects(lambda m: m.update(cmdlin="x"), "unknown key 'cmdlin'")

    def test_rejects_unknown_nested_key(self):
        self.rejects(lambda m: m["launch"].update(vcpu_typ="EPYC-v4"), "launch: unknown key 'vcpu_typ'")

    def test_rejects_unknown_key_in_tool_and_inputs(self):
        self.rejects(lambda m: m["tool"].update(flags="x"), "tool: unknown key")
        self.rejects(lambda m: m["inputs"]["kernel"].update(sha265="x"), "inputs.kernel: unknown key")


class DuplicateKeys(unittest.TestCase):
    def load(self, text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "m.json")
            p.write_text(text)
            return mf.load_manifest(p)

    def test_duplicate_cmdline_is_refused(self):
        text = EXAMPLE.read_text()
        text = text.replace('"cmdline":', '"cmdline": "decoy",\n  "cmdline":', 1)
        self.assertIn('"decoy"', text)
        with self.assertRaises(mf.ManifestError) as cm:
            self.load(text)
        self.assertIn("duplicate key 'cmdline'", str(cm.exception))

    def test_duplicate_nested_key_is_refused(self):
        text = EXAMPLE.read_text().replace('"vcpu_type":', '"vcpu_type": "EPYC",\n    "vcpu_type":', 1)
        with self.assertRaises(mf.ManifestError) as cm:
            self.load(text)
        self.assertIn("duplicate key 'vcpu_type'", str(cm.exception))

    def test_clean_manifest_still_loads(self):
        self.load(EXAMPLE.read_text())


class CmdlineFile(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "cmdline.txt")
            p.write_bytes(data)
            return mf.read_cmdline_file(p)

    def test_one_trailing_newline_is_not_part_of_the_command_line(self):
        self.assertEqual(self.read(b"console=ttyS0 quiet\n"), self.read(b"console=ttyS0 quiet"))
        self.assertEqual(self.read(b"a b\n"), "a b")

    def test_two_trailing_newlines_are_refused(self):
        with self.assertRaises(mf.ManifestError):
            self.read(b"a b\n\n")

    def test_crlf_is_refused(self):
        with self.assertRaises(mf.ManifestError):
            self.read(b"a b\r\n")

    def test_trailing_space_is_kept_and_changes_the_result(self):
        self.assertEqual(self.read(b"a b \n"), "a b ")
        self.assertNotEqual(self.read(b"a b \n"), self.read(b"a b\n"))

    def test_trailing_space_changes_the_measured_value(self):
        with tempfile.TemporaryDirectory() as d:
            tool = fake_tool(d)
            m = good()
            m["cmdline"] = self.read(b"a b\n")
            plain = mf.compute_fingerprint(m, d, 2, tool)
            m["cmdline"] = self.read(b"a b \n")
            spaced = mf.compute_fingerprint(m, d, 2, tool)
            self.assertNotEqual(plain, spaced)

    def test_manifest_cmdline_is_used_exactly_as_written(self):
        m = good()
        m["cmdline"] = "a b\n"
        mf.validate(m)
        self.assertEqual(mf.tool_command(m, "/in", 2)[-1], "a b\n")

    def test_dm_create_file_builds_the_boot_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "desktop.dm-create")
            p.write_bytes(b"desktop,,,ro,0 1 verity\n")
            self.assertEqual(mf.cmdline_from_dm_file(p),
                             'console=ttyS0 rdinit=/init panic=-1 quiet loglevel=0 dm-mod.create="desktop,,,ro,0 1 verity"')


def fake_tool(d, name="fake-tool"):
    """A stand-in for sev-snp-measure: the output depends on every argument it is given."""
    p = Path(d, name)
    p.write_text("#!/bin/sh\n"
                 'if [ "$1" = "--version" ]; then echo "sev-snp-measure 0.0.13"; exit 0; fi\n'
                 "h=$(printf '%s|' \"$@\" | shasum -a 256 | cut -c1-64)\n"
                 "echo \"${h}${h}\" | cut -c1-96\n")
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return str(p)


class RunCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.tool = fake_tool(self.dir)
        self.m = good()
        for name, content in (("firmware", b"fw"), ("kernel", b"kern"), ("initrd", b"rd")):
            (self.dir / self.m["inputs"][name]["file"]).write_bytes(content)
            self.m["inputs"][name]["sha256"] = hashlib.sha256(content).hexdigest()
        self.right = {n: mf.compute_fingerprint(self.m, self.dir, n, self.tool) for n in (2, 4)}

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, expected):
        self.m["expected"] = expected
        p = self.dir / "m.json"
        p.write_text(json.dumps(self.m))
        args = type("A", (), {"manifest": str(p), "inputs_dir": str(self.dir), "tool": self.tool})()
        return mf.run_check(args)

    def test_right_fingerprint_passes(self):
        self.assertEqual(self.check({"2": self.right[2]}), 0)

    def test_wrong_fingerprint_sharing_a_long_prefix_fails(self):
        near = self.right[2][:-1] + ("0" if self.right[2][-1] != "0" else "1")
        self.assertEqual(self.check({"2": near}), 1)

    def test_expected_for_another_vcpu_count_fails(self):
        self.assertNotEqual(self.right[2], self.right[4])
        self.assertEqual(self.check({"4": self.right[2]}), 1)
        self.assertEqual(self.check({"2": self.right[4]}), 1)

    def test_one_wrong_size_among_right_ones_fails(self):
        self.assertEqual(self.check({"2": self.right[2], "4": self.right[2]}), 1)


if __name__ == "__main__":
    unittest.main()
