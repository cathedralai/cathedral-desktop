# What MEASUREMENT covers under Cloud Hypervisor + stage0 (AB#433)

Spike, from source only. No box was booted. Parent: AB#363 (publish the TEE box fingerprint).

## Answer

- **Today (QEMU + OVMF, `kernel-hashes=on`): the kernel, initrd and command line are covered.** QEMU writes their SHA-256 into a hash table page that is part of the launch measurement, and OVMF refuses a blob that does not match it.
- **Cloud Hypervisor + Oak stage0, as stage0 ships by default: the initrd is NOT enforced by MEASUREMENT.** Cloud Hypervisor can measure a hash table, but the default stage0 build never checks the loaded kernel, initrd or command line against it. A host can hash one initrd into the table and serve another over fw_cfg. The box reports the expected MEASUREMENT and our verifiers accept it.
- **Cloud Hypervisor + stage0 built with `sev_kernel_hashes`, launched with fw_cfg `kernel=on,cmdline=on,initramfs=on`: covered, same model as today.** Cloud Hypervisor measures the table, stage0 checks all three blobs against it and halts on a mismatch.
- Use the third configuration. Anything else needs a verifier that reads stage0's DICE event log, which ours do not.
- Under any stage0 build, the box loses VMPL 0 attestation: stage0 wipes VMPCK0 before the kernel runs. boxd and the sealed data key must move to VMPCK1 (VMPL 1). See "stage0 takes VMPL 0" below.
- ACPI tables and the e820 map come from the host over fw_cfg and are not in MEASUREMENT under either stack. That is the same as OVMF today.

## Today's path

- `cathedral-sandbox` `room-kit/sealed/launch-guest.sh:68`: `sev-snp-guest,...,kernel-hashes=on`. Desktop box: `tee/rootfs/RUNBOOK-c48.md` (AB#362 QEMU line, `kernel-hashes=on`).
- The dm-verity root hash rides the command line (`tee/rootfs/README.md`), so the measured command line also pins the rootfs.
- The fingerprint tool in `tee/build/` (merged in #7) computes this with `sev-snp-measure` from OVMF, kernel, initrd and command line. Its run 5 value equals a chip-signed report.

## Cloud Hypervisor (main 5eeaa6b, 13 Nov 2026)

- SEV-SNP on KVM needs an IGVM payload and the `kvm,igvm,sev_snp,fw_cfg` build features (`docs/amd_sev_snp.md`). The fw_cfg feature is not in release binaries (`docs/fw_cfg.md`).
- `vmm/src/sev.rs`: builds the same SEV hash table as QEMU and OVMF (same GUIDs, cmdline hashed with a trailing NUL, kernel as setup + body, missing initrd as hash of empty). It lives at GPA `0x10c00`, size `0x400`.
- `vmm/src/vm.rs` `load_payload` (about line 1689): the table is built only when the payload is IGVM, `--kernel` and `--cmdline` are set, and fw_cfg has `kernel=on` and `cmdline=on`. The initrd is hashed only with fw_cfg `initramfs=on`.
- `vmm/src/igvm/igvm_loader.rs` (about lines 320, 500, 759): the table page is imported as a normal (measured) page on KVM. A parameter area overlapping it is refused. So when the table exists, changing the initrd changes MEASUREMENT.

## Oak stage0 (main d7d7f57, 13 Nov 2026)

- `stage0/src/lib.rs` (about lines 184 to 230): loads command line, kernel and initrd over fw_cfg and hashes each.
- Lines 221 to 230: the only check against the measured table is `P::validate_measured_boot`. A mismatch hits `assert!`, so the box halts.
- The feature is gated in two crates. The `assert!` needs the `stage0` crate's `sev_kernel_hashes` (`stage0/src/lib.rs:221`). The real validator needs the `stage0_sev` crate's (`stage0_sev/src/platform/mod.rs:360`); without it the stub returns `true`. Both must be on, or the check silently stays off.
- That feature is commented out in `stage0/BUILD:29` and `stage0_sev/BUILD:28`. Without it, the stub at `stage0_sev/src/platform/mod.rs:384` returns `true` (`:391`) and logs "sev_kernel_hashes is not compiled, skipping".
- `stage0_sev/src/platform/kernel_hash_tables.rs`: the table layout matches Cloud Hypervisor's (cmdline, initrd, kernel at fixed offsets). The GUIDs match only in a comment (`:17-22`); `validate_hash_table` (`:62-112`) reads fixed offsets and does not check GUIDs or lengths. `stage0_bin/layout.ld:127` places it at `0x10c00`, the same address.
- Without the check, stage0 reports the digests only in its DICE evidence. `stage0_dice/src/lib.rs:120-131` puts sha256 of stage0's ECA public key in REPORT_DATA. The kernel, initrd and command line digests go into a stage0 event that the ECA key signs, not into MEASUREMENT or REPORT_DATA.
- stage0 also derives a sealing CDI from those digests, initrd included (`stage0/src/lib.rs` about line 264). That is a possible alternative to a MEASUREMENT-only volume key. Not pursued here.
- Oak at d7d7f57 has no IGVM build: `stage0_bin/BUILD` only makes a BIOS blob. The stage0 IGVM must be produced outside Oak, and whoever produces it owns turning on `sev_kernel_hashes`.

## stage0 takes VMPL 0

- `stage0_sev/src/platform/dice_attestation.rs:44-52`: after using VMPCK0, stage0 wipes it and fills it with 0xFF so that "later boot stages cannot request attestation reports or derived sealing keys for VMPL0".
- stage0 hands VMPCK1 to 3 to the kernel through the secrets page (`stage0_sev/src/platform/mod.rs:320-328`).
- So under stage0, boxd's report (`tee/boxd/main.go` `attest`, configfs-tsm at the default VMPCK) and `sealed_data_key.py:58` (`VMPL = 0`) fail as shipped. The guest needs `sev-guest.vmpck_id=1` and the sealed key must request VMPL 1. The VMPL 1 key differs from today's VMPL 0 key.
- Neither verifier checks the report's VMPL field (`snp-verify.js:135` parses it and never reads it; `sealed_stream.py` does not look at it). So without `sev_kernel_hashes`, a kernel with a swapped initrd still gets a report and a key our verifiers accept. The conclusion above stands.
- Requiring VMPL 0 in the verifiers would rule out stage0 entirely, or force the DICE path.

## Why the default stage0 build is not enough for us

- Our verifiers check the AMD chain, policy bits, TCB floor, the REPORT_DATA binding and MEASUREMENT: `tee/client/sealed_stream.py:140` (REPORT_DATA) and `:168-172` (MEASUREMENT), `tee/web/snp-verify.js:223-228`. Neither reads a DICE event log.
- Our report comes from boxd after boot, not from stage0. Any kernel that boots can ask the chip for a report with its own REPORT_DATA (at VMPL 1 under stage0, see above). MEASUREMENT does not change with the initrd unless the hash table is both measured and enforced.
- The sealed data volume key (`cathedral-sandbox` `room-kit/sealed/sealed_data_key.py:56`, `docs/SEALED_DATA_VOLUME.md:81`) binds MEASUREMENT and policy. An unenforced initrd would derive the same key and could open a customer's workspace.
- A naive check on a host gives a false pass. With stock Cloud Hypervisor, two boxes that differ only in initrd will show different MEASUREMENTs, because the table is measured. That proves measurement, not enforcement. A negative control must serve a different initrd than the one hashed.

## What changes in the fingerprint

- Inputs become: the stage0 IGVM file, kernel, initrd, command line, vCPU count and type, guest features, policy and the Cloud Hypervisor version.
- The `tee/build/` tool reads OVMF as its firmware input through `sev-snp-measure`. It does not model an IGVM launch. An IGVM-aware calculator has to be added and checked against one chip-signed report, as run 5 was for QEMU.

## Needs an AMD host (not done here)

1. Build stage0 with `sev_kernel_hashes` on in both `stage0/BUILD` and `stage0_sev/BUILD`, and package it as IGVM; build Cloud Hypervisor with `kvm,igvm,sev_snp,fw_cfg`. Add `sev-guest.vmpck_id=1` to the command line and move `sealed_data_key.py` to VMPL 1, or no report or key comes back.
2. Boot two boxes that differ only in initrd. Expect two MEASUREMENTs.
3. Negative control: serve an initrd that differs from the hashed one. Passing a new `--initramfs` path does not do it: Cloud Hypervisor hashes and serves the same path. The table is built at VM create (`vmm/src/vm.rs` `load_payload`, about 1689 to 1725) and the fw_cfg file is opened at boot (`populate_fw_cfg`, about 1192 to 1204 and 2499) and read lazily (`devices/src/legacy/fw_cfg.rs` about 675 and 695). So create the VM, swap the file at that path, then boot. A patched VMM also works. Expect stage0 to halt before the kernel runs.
4. Optional, to confirm the gap: repeat step 3 with the default stage0 build. Expect a box that boots and reports the expected MEASUREMENT.
5. Compute the expected fingerprint offline, compare it with the live report, and check that `sealed_stream.py` refuses a box whose MEASUREMENT is not pinned.

## Not checked

- Who produces the stage0 IGVM file (Oak has no IGVM build; see above).
- stage0 with `sev_kernel_hashes` on but no table from the VMM. Expected to fail closed: an empty table cannot match. Not run.
- Lazy accept and memory use under Cloud Hypervisor: that is AB#431.
