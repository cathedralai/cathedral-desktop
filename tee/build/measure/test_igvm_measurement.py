"""Tests for the Cloud Hypervisor + stage0 IGVM fingerprint calculator (AB#433).

The main test recomputes every chip-signed MEASUREMENT recorded on the SNP test host from the saved
IGVM files and the recorded input hashes. No AMD host, no kernel or initrd files, standard library only.
When sev-snp-measure is importable (the pinned venv), the hash table and launch digest are also
compared with it.
"""
import hashlib
import json
import os
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import igvm_measurement as im  # noqa: E402

DATA = Path(__file__).resolve().parent / "testdata" / "igvm"
CASES = json.loads((DATA / "chip-cases.json").read_text())
# The regenerated fingerprint for the enforcing stage0 with the test kernel and initrd A (card AB#433).
ENFORCING_TEST_FINGERPRINT = (
    "1c69dec20183da277d24d4a61cd081ffbaaa224beba75cdf4d13538946967a101b938bae83c5926b00e9546d82b746d2"
)


def igvm(name):
    return (DATA / name).read_bytes()


def inputs(case):
    k = bytes.fromhex(CASES["inputs"][case["kernel"]])
    i = bytes.fromhex(CASES["inputs"][case["initrd"]])
    return k, i, CASES["cmdline_base"] + case["cmdline_suffix"]


class ChipCases(unittest.TestCase):
    def test_saved_igvm_files_are_the_booted_ones(self):
        for name, want in CASES["igvm"].items():
            self.assertEqual(hashlib.sha256(igvm(name)).hexdigest(), want, name)

    def test_every_recorded_chip_measurement_is_reproduced(self):
        self.assertEqual(len(CASES["cases"]), 11)
        for case in CASES["cases"]:
            with self.subTest(boot=case["boot"]):
                got = im.measurement(igvm(case["igvm"]), *inputs(case)).hex()
                self.assertEqual(got, case["chip"])

    def test_enforcing_stage0_test_fingerprint(self):
        k = bytes.fromhex(CASES["inputs"]["vmlinuz"])
        i = bytes.fromhex(CASES["inputs"]["initrd-A"])
        got = im.measurement(igvm("stage0-kernelhashes.igvm"), k, i, CASES["cmdline_base"]).hex()
        self.assertEqual(got, ENFORCING_TEST_FINGERPRINT)

    def test_stale_default_fingerprint_differs_from_enforcing(self):
        # The pinned value has to move with the stage0 build: the same inputs give another number.
        k = bytes.fromhex(CASES["inputs"]["vmlinuz"])
        i = bytes.fromhex(CASES["inputs"]["initrd-A"])
        a = im.measurement(igvm("stage0-default.igvm"), k, i, CASES["cmdline_base"])
        b = im.measurement(igvm("stage0-kernelhashes.igvm"), k, i, CASES["cmdline_base"])
        self.assertNotEqual(a, b)

    def test_each_input_changes_the_fingerprint(self):
        base = CASES["cases"][0]
        k, i, c = inputs(base)
        ref = im.measurement(igvm(base["igvm"]), k, i, c)
        flipped = bytes([k[0] ^ 1]) + k[1:]
        self.assertNotEqual(im.measurement(igvm(base["igvm"]), flipped, i, c), ref)
        self.assertNotEqual(im.measurement(igvm(base["igvm"]), k, flipped, c), ref)
        self.assertNotEqual(im.measurement(igvm(base["igvm"]), k, i, c + " "), ref)

    def test_cli_with_recorded_hashes(self):
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = im.main([
                str(DATA / "stage0-kernelhashes.igvm"),
                "--kernel-sha256", CASES["inputs"]["vmlinuz"],
                "--initrd-sha256", CASES["inputs"]["initrd-A"],
                "--cmdline", CASES["cmdline_base"],
            ])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().strip(), ENFORCING_TEST_FINGERPRINT)


def _vh(typ, body):
    return struct.pack("<II", typ, len(body)) + body + bytes(-len(body) % 8)


def _igvm_file(directives, version=1):
    """Smallest IGVM file: one SEV-SNP platform header, the given directives, then 4K file data."""
    platform = _vh(im.VHT_SUPPORTED_PLATFORM, struct.pack("<IBBHQ", 1, 0, im.PLATFORM_SEV_SNP, 1, 0))
    vh_off = 24
    # Build once to size the headers, then lay out file data after them.
    headers = platform + b"".join(_vh(t, b) for t, b, _ in directives)
    data_off = (vh_off + len(headers) + 4095) & ~4095
    file_data = b""
    vhs = platform
    for typ, body, payload in directives:
        if payload is not None:
            off = data_off + len(file_data)
            body = body.replace(b"\xee\xee\xee\xee", struct.pack("<I", off))
            file_data += payload
        vhs += _vh(typ, body)
    pad = bytes(data_off - vh_off - len(vhs))
    total = vh_off + len(vhs) + len(pad) + len(file_data)
    return struct.pack("<6I", im.IGVM_MAGIC, version, vh_off, len(vhs), total, 0) + vhs + pad + file_data


def _page(gpa, payload=None, flags=0, dtype=0):
    off = b"\xee\xee\xee\xee" if payload is not None else bytes(4)
    return (im.VHT_PAGE_DATA, struct.pack("<QI", gpa, 1) + off + struct.pack("<IHH", flags, dtype, 0), payload)


def _vmsa(gpa=im.VMSA_GPA, vp=0):
    return (im.VHT_VP_CONTEXT, struct.pack("<QI", gpa, 1) + b"\xee\xee\xee\xee" + struct.pack("<HHI", vp, 0, 0), bytes(4096))


class Parser(unittest.TestCase):
    def test_minimal_file_parses(self):
        f = _igvm_file([_page(0x1000, b"\x01" * 4096), _page(0x2000), _vmsa()])
        d = im.parse_igvm(f)
        self.assertEqual([x[0] for x in d], ["page", "page", "vmsa"])
        self.assertEqual(d[1][3], b"")

    def refuses(self, directives, text, **kw):
        with self.assertRaises(im.IgvmError) as cm:
            im.parse_igvm(_igvm_file(directives, **kw))
        self.assertIn(text, str(cm.exception))

    def test_refuses_unmeasured_page(self):
        self.refuses([_page(0x1000, flags=0x2), _vmsa()], "flags")

    def test_refuses_page_over_hash_page(self):
        self.refuses([_page(im.HASH_PAGE_GPA, b"\0" * 4096), _vmsa()], "hash page")

    def test_refuses_unmodelled_directive(self):
        self.refuses([(0x303, bytes(16), None), _vmsa()], "not modelled")

    def test_refuses_two_vcpus(self):
        self.refuses([_vmsa(), _vmsa(vp=1)], "exactly one")

    def test_refuses_other_format_version(self):
        self.refuses([_vmsa()], "version", version=2)

    def test_refuses_bad_magic(self):
        with self.assertRaises(im.IgvmError):
            im.parse_igvm(b"NOPE" + bytes(100))


try:
    from sevsnpmeasure.gctx import GCTX
    from sevsnpmeasure.sev_hashes import SevHashes
except ImportError:  # plain python3 in CI; the venv step runs these
    GCTX = None


@unittest.skipIf(GCTX is None, "sev-snp-measure not installed")
class AgainstSevSnpMeasure(unittest.TestCase):
    def test_hash_page_matches_sevhashes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            kp, ip = Path(d, "k"), Path(d, "i")
            kp.write_bytes(b"kernel bytes")
            ip.write_bytes(b"initrd bytes")
            want = SevHashes(str(kp), str(ip), "console=ttyS0 x").construct_page(im.HASH_TABLE_OFFSET)
        got = im.hash_page(hashlib.sha256(b"kernel bytes").digest(), hashlib.sha256(b"initrd bytes").digest(),
                           "console=ttyS0 x")
        self.assertEqual(got, want)

    def test_launch_digest_matches_gctx(self):
        g, ld = GCTX(), im.LaunchDigest()
        page = bytes(range(256)) * 16
        g.update_normal_pages(0x1000, page); ld.normal(0x1000, page)
        g.update_zero_pages(0x2000, 4096); ld.zero(0x2000)
        g.update_secrets_page(0x3000); ld.secrets(0x3000)
        g.update_cpuid_page(0x4000); ld.cpuid(0x4000)
        g.update_vmsa_page(page); ld.vmsa(page)
        self.assertEqual(ld.ld, g.ld())


if __name__ == "__main__":
    unittest.main()
