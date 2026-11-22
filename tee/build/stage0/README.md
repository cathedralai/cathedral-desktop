# Enforcing stage0 for the Cloud Hypervisor box (AB#433)

Cloud Hypervisor + Oak stage0 only covers the kernel, initrd and command line if stage0 is built with
`sev_kernel_hashes`. The default build measures the hash table but never checks the loaded blobs
against it (`tee/MEASUREMENT-COVERAGE.md`). This folder pins the build that does check them.

## Build

```
tee/build/stage0/build-stage0.sh [WORKDIR]
```

| Input | Pin |
|---|---|
| Oak | `f07cdb50315cbb3dff7dd4b0e6b9505f425bf42e` + `oak-sev_kernel_hashes.patch` |
| Bazel | 8.5.1 (Oak's `.bazelversion`) |
| buildigvm | `58264592c62ca8828de4874870de0fd2e8ae3dbf`, `--cpucount 1 sev-snp` |
| `stage0_bin` | sha256 `350034b47d06f92f4a693e7b11a36f876375e69a1048e2dfd26d2f58351a2b4d` |
| `stage0-kernelhashes.igvm` | sha256 `6f2606fb7efd8a8ce3776ea31bb0d194af621d8d87f2e0f810aa3a039e84997e` |

The IGVM file is also saved as `tee/build/measure/testdata/igvm/stage0-kernelhashes.igvm`.
Wrapping the saved `stage0_bin` with buildigvm reproduces the IGVM sha256 exactly (checked for both
the enforcing and the default build).

## Launch

The table is only built when all three fw_cfg items are on:

```
cloud-hypervisor --igvm stage0-kernelhashes.igvm --kernel KERNEL --initramfs INITRD --cmdline 'CMDLINE' \
  --fw-cfg-config kernel=on,cmdline=on,initramfs=on --platform sev_snp=on --cpus boot=1 ...
```

Cloud Hypervisor needs the `kvm,igvm,sev_snp,fw_cfg` features (5eeaa6bd was used).

## Fingerprint

```
python3 -I tee/build/measure/igvm_measurement.py stage0-kernelhashes.igvm \
  --kernel KERNEL --initrd INITRD --cmdline 'CMDLINE'
```

`--kernel-sha256` and `--initrd-sha256` take recorded hashes instead of files. The calculator
replays Cloud Hypervisor's IGVM loader for KVM (IGVM pages in file order, then the hash page at
0x10000, then the boot vCPU VMSA). It refuses an IGVM file with anything it does not model
(unmeasured or shared pages, parameter areas, more than one vCPU).

For the test kernel (`ba394340...`), initrd A (`2677105c...`) and the command line
`console=ttyS0 panic=-1 sev_guest.vmpck_id=1`, the enforcing stage0 gives

`1c69dec20183da277d24d4a61cd081ffbaaa224beba75cdf4d13538946967a101b938bae83c5926b00e9546d82b746d2`

`test_igvm_measurement.py` recomputes all 11 chip-signed values recorded on the SNP test host
(both stage0 builds, initrd A and B, two command lines, two kernels) from the saved IGVM files and
the recorded input hashes. This is a test fingerprint, not the box image's: the box image has no
Cloud Hypervisor build yet.

## Negative control (SNP test host, 22 Nov 2026)

Cloud Hypervisor 5eeaa6bd with a test-only patch that writes the hash of one blob into the measured
table while serving another, which models a host that measures the expected inputs and serves
others. The patch is evidence, not product code; it is attached to card AB#433
(`ch-ab433-harness.patch`, sha256 `b6f24d26...5d76da`). 1 vCPU, 1 GiB, 60 s per boot.

| stage0 | Served | Hashed | Result | MEASUREMENT |
|---|---|---|---|---|
| default | initrd B | initrd A | runs B | `511dea4b` (A's value: false pass) |
| default | base cmdline | base + ` quiet` | runs base | `ce86988c` (false pass) |
| default | vmlinuz | bzImage | runs vmlinuz | `aceee6eb` (false pass) |
| enforcing | initrd A | initrd A | runs A (twice) | `1c69dec2` |
| enforcing | initrd B | initrd B | runs B | `84bd546e` |
| enforcing | initrd B | initrd A | halts: `initrd check failed`, then `assertion failed: P::validate_measured_boot` (stage0/src/lib.rs:226), reboot loop, Linux never starts | none |
| enforcing | base cmdline | base + ` quiet` | halts: `kernel cmdline check failed`, same assertion | none |
| enforcing | vmlinuz | bzImage | halts: `Kernel check failed`, same assertion | none |

- With the default build, the initrd, kernel and command line are measured but not enforced.
- With `sev_kernel_hashes`, all three are enforced.
- The shipped verifiers (`tee/client/sealed_stream.py`, `tee/web/snp-verify.js`, main 554030b9)
  accept the `1c69dec2` report when that value is pinned and refuse it when the stale default
  value `511dea4b` is pinned. Boot logs and reports are on card AB#433 (comment 32994381).

## Not done here

- The box image build does not use this stage0 yet, and there is no fingerprint for the real box
  image under Cloud Hypervisor. Both follow when the box moves to Cloud Hypervisor.
- A stage0 rebuild was bit-identical on the SNP test host. It has not been rebuilt on a second machine.
