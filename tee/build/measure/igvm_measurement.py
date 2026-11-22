#!/usr/bin/env python3
"""SEV-SNP launch fingerprint (MEASUREMENT) for Cloud Hypervisor + an Oak stage0 IGVM file (AB#433).

sev-snp-measure models QEMU + OVMF. It does not model an IGVM launch, so this file replays what
Cloud Hypervisor 5eeaa6bd (vmm/src/igvm/igvm_loader.rs) asks KVM to measure, in this order:

  1. the IGVM page directives for SEV-SNP, in file order (normal, zero, secrets and CPUID pages);
  2. the SEV hash page at GPA 0x10000 with the kernel, initrd and command line table at offset 0xc00.
     Cloud Hypervisor appends it as a normal page when no IGVM page covers it and fw_cfg has
     kernel=on,cmdline=on,initramfs=on;
  3. the boot vCPU VMSA, measured by KVM at LAUNCH_FINISH. Traced on the SNP test host, the VMSA KVM
     measures equals the IGVM VP context byte for byte. The QEMU VMSA model sev-snp-measure uses
     does not (GDTR and IDTR limits differ), which is why it gives the wrong value here.

Standard library only. The kernel and initrd enter only through their sha256, so a fingerprint can
be checked from recorded hashes without the files. The table layout matches sev-snp-measure's
SevHashes (the unit tests compare the two when the pinned tool is installed).

Usage:
  igvm_measurement.py IGVM (--kernel FILE | --kernel-sha256 HEX) (--initrd FILE | --initrd-sha256 HEX)
                      --cmdline STRING
"""
import argparse
import hashlib
import struct
import sys
import uuid

PAGE = 4096
IGVM_MAGIC = 0x4D564749  # "IGVM"
VHT_SUPPORTED_PLATFORM = 0x1
VHT_PAGE_DATA = 0x302
VHT_VP_CONTEXT = 0x304
PLATFORM_SEV_SNP = 0x02
PAGE_NORMAL, PAGE_SECRETS, PAGE_CPUID_DATA = 0x0, 0x1, 0x2

# Cloud Hypervisor vmm/src/sev.rs and Oak stage0_bin/layout.ld: the table lives at GPA 0x10c00.
HASH_PAGE_GPA = 0x10000
HASH_TABLE_OFFSET = 0xC00
VMSA_GPA = 0xFFFFFFFFF000

HASH_TABLE_GUID = "9438d606-4f22-4cc9-b479-a793d411fd21"
CMDLINE_GUID = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a"
INITRD_GUID = "44baf731-3a2f-4bd7-9af1-41e29169781d"
KERNEL_GUID = "4de79437-abd2-427f-b835-d5b172d2045b"


class IgvmError(ValueError):
    pass


def parse_igvm(data):
    """Return the SEV-SNP directives of an IGVM file in file order.

    Each item is ("page", gpa, data_type, bytes or b"" for a zero page) or ("vmsa", gpa, vp_index, bytes).
    Anything this calculator does not model (unmeasured, shared or 2 MB pages, more than one VP
    context, a page over the hash page) is refused rather than skipped.
    """
    if len(data) < 24:
        raise IgvmError("file shorter than the IGVM fixed header")
    magic, version, vh_off, vh_size, total, _crc = struct.unpack_from("<6I", data, 0)
    if magic != IGVM_MAGIC:
        raise IgvmError("not an IGVM file (bad magic)")
    if version != 1:
        raise IgvmError(f"IGVM format version {version} is not modelled (only 1)")
    if total != len(data) or vh_off + vh_size > len(data):
        raise IgvmError("IGVM header sizes do not match the file")

    snp_mask = None
    out = []
    pos, end = vh_off, vh_off + vh_size
    while pos < end:
        typ, length = struct.unpack_from("<II", data, pos)
        body = data[pos + 8:pos + 8 + length]
        pos += 8 + ((length + 7) & ~7)
        if typ == VHT_SUPPORTED_PLATFORM:
            mask, _vtl, platform, _pver = struct.unpack_from("<IBBH", body, 0)
            if platform == PLATFORM_SEV_SNP:
                snp_mask = mask
            continue
        if typ not in (VHT_PAGE_DATA, VHT_VP_CONTEXT):
            # Init headers (policy, relocation) do not reach KVM. Any other directive (parameter
            # area or insert, required memory, ID block, ...) may add pages to the measurement,
            # so fail closed. The stage0 IGVM files carry none.
            if 0x101 <= typ <= 0x200:
                continue
            raise IgvmError(f"IGVM directive type {typ:#x} is not modelled")
        if snp_mask is None:
            raise IgvmError("IGVM file has no SEV-SNP platform header before its directives")
        if typ == VHT_PAGE_DATA:
            gpa, mask, file_off, flags, dtype, reserved = struct.unpack_from("<QIIIHH", body, 0)
            if not mask & snp_mask:
                continue
            if flags != 0 or reserved != 0:
                raise IgvmError(f"page {gpa:#x} has flags {flags:#x}; only plain measured 4K pages are modelled")
            if gpa & (PAGE - 1):
                raise IgvmError(f"page {gpa:#x} is not 4K aligned")
            if gpa == HASH_PAGE_GPA:
                raise IgvmError("an IGVM page covers the hash page; Cloud Hypervisor would not append it")
            if file_off == 0:
                payload = b""
            else:
                payload = data[file_off:file_off + PAGE]
                if len(payload) != PAGE:
                    raise IgvmError(f"page {gpa:#x} data runs past the end of the file")
            if dtype not in (PAGE_NORMAL, PAGE_SECRETS, PAGE_CPUID_DATA):
                raise IgvmError(f"page {gpa:#x} type {dtype:#x} is not modelled")
            out.append(("page", gpa, dtype, payload))
        else:
            gpa, mask, file_off, vp_index, _r = struct.unpack_from("<QIIHH", body, 0)
            if not mask & snp_mask:
                continue
            vmsa = data[file_off:file_off + PAGE]
            if len(vmsa) != PAGE:
                raise IgvmError("VP context data runs past the end of the file")
            out.append(("vmsa", gpa, vp_index, vmsa))
    vmsas = [d for d in out if d[0] == "vmsa"]
    if len(vmsas) != 1 or vmsas[0][1] != VMSA_GPA or vmsas[0][2] != 0:
        raise IgvmError("expected exactly one SEV-SNP VP context, vp 0 at the VMSA GPA (1 vCPU)")
    return out


def hash_table(kernel_sha256, initrd_sha256, cmdline):
    """The SEV hash table Cloud Hypervisor builds (same layout as QEMU and sev-snp-measure).

    The command line is hashed with a trailing NUL. The kernel and initrd hashes are sha256 of the
    whole files as served over fw_cfg.
    """
    cmdline_sha256 = hashlib.sha256(cmdline.encode() + b"\0").digest()

    def entry(guid, digest):
        if len(digest) != 32:
            raise ValueError("sha256 digest must be 32 bytes")
        return uuid.UUID(guid).bytes_le + struct.pack("<H", 50) + digest

    body = entry(CMDLINE_GUID, cmdline_sha256) + entry(INITRD_GUID, initrd_sha256) + entry(KERNEL_GUID, kernel_sha256)
    table = uuid.UUID(HASH_TABLE_GUID).bytes_le + struct.pack("<H", 18 + len(body)) + body
    return table + bytes(-len(table) % 16)


def hash_page(kernel_sha256, initrd_sha256, cmdline):
    table = hash_table(kernel_sha256, initrd_sha256, cmdline)
    return bytes(HASH_TABLE_OFFSET) + table + bytes(PAGE - HASH_TABLE_OFFSET - len(table))


class LaunchDigest:
    """SNP launch digest: SHA-384 over PAGE_INFO structures (SNP firmware ABI, PAGE_INFO layout)."""

    def __init__(self):
        self.ld = bytes(48)

    def update(self, page_type, gpa, contents_digest):
        info = self.ld + contents_digest + struct.pack("<HBBBBBBQ", 0x70, page_type, 0, 0, 0, 0, 0, gpa)
        self.ld = hashlib.sha384(info).digest()

    def normal(self, gpa, page):
        self.update(0x01, gpa, hashlib.sha384(page).digest())

    def vmsa(self, page):
        self.update(0x02, VMSA_GPA, hashlib.sha384(page).digest())

    def zero(self, gpa):
        self.update(0x03, gpa, bytes(48))

    def secrets(self, gpa):
        self.update(0x05, gpa, bytes(48))

    def cpuid(self, gpa):
        self.update(0x06, gpa, bytes(48))


def measurement(igvm_bytes, kernel_sha256, initrd_sha256, cmdline):
    """Expected MEASUREMENT (48 bytes) for this IGVM file and these boot inputs."""
    ld = LaunchDigest()
    vmsa = None
    for d in parse_igvm(igvm_bytes):
        if d[0] == "vmsa":
            vmsa = d[3]
            continue
        _, gpa, dtype, payload = d
        if dtype == PAGE_CPUID_DATA:
            ld.cpuid(gpa)
        elif dtype == PAGE_SECRETS:
            ld.secrets(gpa)
        elif not payload:
            ld.zero(gpa)
        else:
            ld.normal(gpa, payload)
    ld.normal(HASH_PAGE_GPA, hash_page(kernel_sha256, initrd_sha256, cmdline))
    ld.vmsa(vmsa)
    return ld.ld


def _sha256_arg(path, hexstr, name):
    if (path is None) == (hexstr is None):
        raise SystemExit(f"give exactly one of --{name} and --{name}-sha256")
    if hexstr is not None:
        b = bytes.fromhex(hexstr)
        if len(b) != 32:
            raise SystemExit(f"--{name}-sha256 must be 64 hex characters")
        return b
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def main(argv=None):
    p = argparse.ArgumentParser(description="SEV-SNP MEASUREMENT for Cloud Hypervisor + stage0 IGVM")
    p.add_argument("igvm")
    p.add_argument("--kernel")
    p.add_argument("--kernel-sha256")
    p.add_argument("--initrd")
    p.add_argument("--initrd-sha256")
    p.add_argument("--cmdline", required=True, help="exact command line, without the trailing NUL")
    a = p.parse_args(argv)
    k = _sha256_arg(a.kernel, a.kernel_sha256, "kernel")
    i = _sha256_arg(a.initrd, a.initrd_sha256, "initrd")
    with open(a.igvm, "rb") as f:
        igvm = f.read()
    try:
        print(measurement(igvm, k, i, a.cmdline).hex())
    except IgvmError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
