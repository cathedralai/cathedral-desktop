# What MEASUREMENT covers under Cloud Hypervisor + stage0 (AB#433)

Spike, from source only. No box was booted. Parent: AB#363 (publish the TEE box fingerprint).

## Answer

- **Today (QEMU + OVMF, `kernel-hashes=on`): the kernel, initrd and command line are covered.** QEMU writes their SHA-256 into a hash table page that is part of the launch measurement, and OVMF refuses a blob that does not match it.
- **Cloud Hypervisor + Oak stage0, as stage0 ships by default: the initrd is NOT enforced by MEASUREMENT.** Cloud Hypervisor can measure a hash table, but the default stage0 build never checks the loaded kernel, initrd or command line against it. A host can hash one initrd into the table and serve another over fw_cfg. The box reports the expected MEASUREMENT and our verifiers accept it.
- **Cloud Hypervisor + stage0 built with `sev_kernel_hashes`, launched with fw_cfg `kernel=on,cmdline=on,initramfs=on`: covered, same model as today.** Cloud Hypervisor measures the table, stage0 checks all three blobs against it and halts on a mismatch.
- Use the third configuration. Anything else needs a verifier that reads stage0's DICE event log, which ours do not.

## Today's path

- `cathedral-sandbox` `room-kit/sealed/launch-guest.sh:68`: `sev-snp-guest,...,kernel-hashes=on`. Desktop box: `tee/rootfs/RUNBOOK-c48.md` (AB#362 QEMU line, `kernel-hashes=on`).
- The dm-verity root hash rides the command line (`tee/rootfs/README.md`), so the measured command line also pins the rootfs.
- The fingerprint tool from PR #7 (`tee/build/measure/`) computes this with `sev-snp-measure` from OVMF, kernel, initrd and command line. Its run 5 value equals a chip-signed report.

## Cloud Hypervisor (main 5eeaa6b, 13 Nov 2026)

- SEV-SNP on KVM needs an IGVM payload and the `kvm,igvm,sev_snp,fw_cfg` build features (`docs/amd_sev_snp.md`). The fw_cfg feature is not in release binaries (`docs/fw_cfg.md`).
- `vmm/src/sev.rs`: builds the same SEV hash table as QEMU and OVMF (same GUIDs, cmdline hashed with a trailing NUL, kernel as setup + body, missing initrd as hash of empty). It lives at GPA `0x10c00`, size `0x400`.
- `vmm/src/vm.rs` `load_payload` (about line 1689): the table is built only when the payload is IGVM, `--kernel` and `--cmdline` are set, and fw_cfg has `kernel=on` and `cmdline=on`. The initrd is hashed only with fw_cfg `initramfs=on`.
- `vmm/src/igvm/igvm_loader.rs` (about lines 320, 500, 759): the table page is imported as a normal (measured) page on KVM. A parameter area overlapping it is refused. So when the table exists, changing the initrd changes MEASUREMENT.

## Oak stage0 (main d7d7f57, 13 Nov 2026)

- `stage0/src/lib.rs` (about lines 184 to 230): loads command line, kernel and initrd over fw_cfg and hashes each.
- Lines 221 to 230: the only check against the measured table is `P::validate_measured_boot`, compiled only with feature `sev_kernel_hashes`. A mismatch hits `assert!`, so the box halts.
- That feature is commented out in `stage0/BUILD:29` and `stage0_sev/BUILD:28`. Without it, `stage0_sev/src/platform/mod.rs:384` returns `true` and logs "sev_kernel_hashes is not compiled, skipping".
- `stage0_sev/src/platform/kernel_hash_tables.rs`: the table layout and GUIDs match Cloud Hypervisor's. `stage0_bin/layout.ld:127` places it at `0x10c00`, the same address.
- Without the check, stage0 reports the digests only in its DICE evidence. `stage0_dice/src/lib.rs:120-131` puts sha256 of stage0's ECA public key in REPORT_DATA. The kernel, initrd and command line digests go into a stage0 event that the ECA key signs, not into MEASUREMENT or REPORT_DATA.

## Why the default stage0 build is not enough for us

- Our verifiers check MEASUREMENT, the REPORT_DATA binding and a firmware (TCB) floor: `tee/client/sealed_stream.py:131-141,168-172`, `tee/web/snp-verify.js:219-228`. Neither reads a DICE event log, so neither sees stage0's kernel, initrd or command line digests.
- Our report comes from boxd after boot, not from stage0. Any kernel that boots can ask the chip for a report with its own REPORT_DATA. MEASUREMENT does not change with the initrd unless the hash table is both measured and enforced.
- The sealed data volume key (`cathedral-sandbox` `room-kit/sealed/sealed_data_key.py:56`, `docs/SEALED_DATA_VOLUME.md:81`) binds MEASUREMENT and policy. An unenforced initrd would derive the same key and could open a customer's workspace.
- A naive check on a host gives a false pass. With stock Cloud Hypervisor, two boxes that differ only in initrd will show different MEASUREMENTs, because the table is measured. That shows measurement, not enforcement. A negative control must serve a different initrd than the one hashed.

## What changes in the fingerprint

- Inputs become: the stage0 IGVM file, kernel, initrd, command line, vCPU count and type, policy and the Cloud Hypervisor version.
- The PR #7 tool reads OVMF as its firmware input through `sev-snp-measure`. It does not model an IGVM launch. An IGVM-aware calculator has to be added and checked against one chip-signed report, as run 5 was for QEMU. Done in AB#433: `tee/build/measure/igvm_measurement.py` reproduces 11 chip-signed values; the enforcing stage0 build and the negative control are in `tee/build/stage0/README.md`.

## Needs an AMD host (not done here)

1. Build stage0 with `sev_kernel_hashes` and its IGVM; build Cloud Hypervisor with `kvm,igvm,sev_snp,fw_cfg`.
2. Boot two boxes that differ only in initrd. Expect two MEASUREMENTs.
3. Negative control: serve an initrd that differs from the hashed one. Expect stage0 to halt before the kernel runs.
4. Optional, to confirm the gap: repeat step 3 with the default stage0 build. Expect a box that boots and reports the expected MEASUREMENT.
5. Compute the expected fingerprint offline, compare it with the live report, and check that `sealed_stream.py` refuses a box whose MEASUREMENT is not pinned.

## Not checked

- Who produces the stage0 IGVM file, and whether Oak's IGVM build turns on `sev_kernel_hashes`. Only the Bazel files read here were checked.
- stage0 with `sev_kernel_hashes` on but no table from the VMM. Expected to fail closed: an empty table cannot match. Not run.
- Lazy accept and memory use under Cloud Hypervisor: that is AB#431.
