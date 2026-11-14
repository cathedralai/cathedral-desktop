# Launch fingerprint of the desktop TEE box (AB#353)

The fingerprint is the SEV-SNP launch measurement the chip signs into an attestation report
(the MEASUREMENT field, 48 bytes). A customer compares it with a value they computed themselves.
This folder holds the part that can be checked today without AMD hardware: the manifest format and a
script that computes the fingerprint from the inputs and compares it with the manifest.

## Run the check

Needs Python 3.11 or newer (a pinned dependency needs it) and pypi.org once (the tool is installed into a virtual environment from
`measure/requirements.txt`, every file pinned by sha256).

```
tee/build/measure/check.sh MANIFEST INPUTS_DIR
tee/build/measure/expected-measurement.sh MANIFEST INPUTS_DIR [VCPUS]   # print only
python3 -I -m unittest discover -s tee/build/measure                    # no inputs needed; the report
                                                                         # signature tests also need node 22+
```

`check.sh` fails (exit 1) unless all three hold:
1. the installed `sev-snp-measure` is the version the manifest pins;
2. the sha256 of the firmware, kernel and initrd in `INPUTS_DIR` equals the manifest's;
3. the computed fingerprint equals the manifest's, for every vCPU count the manifest lists.

`manifests/run5-example.manifest.json` describes run 5 (hashes and parameters only, no binaries).
Its files are the ones named under `inputs`; put them in one folder and pass that folder.

## Manifest

Shape in `manifest.schema.json`, enforced by `measure/manifest.py`. It holds the three input files by
hash, the exact kernel command line (which carries the dm-verity root hash), the launch parameters
that change the number (CPU model, `guest_features`, `vmm_type`; none is left to the tool's default),
and one expected fingerprint per vCPU count.

The parser is strict. `tool.mode` must be exactly `snp`. Any key the schema does not name is an
error at every level, and so is a key that appears twice in one object, so a misspelled or doubled
field cannot be ignored. In a manifest, `cmdline` is a JSON string used exactly as written.
A command line saved in a FILE (as the control reads them) may end with exactly one newline, which is
the file's line ending and not part of the command line. Any other trailing newline or carriage return
is an error; a trailing space is kept and changes the fingerprint.

## Per-size fingerprints

The measurement covers every vCPU, so a box with another vCPU count has another fingerprint. The
manifest lists one fingerprint per sold size under `expected`. Guest memory size is not measured. The
CPU model (`-cpu EPYC-v4`) is, and so is `kernel-hashes=on`. Nothing per box may ride on the
command line: run 4 showed a per-box IP there gave each box its own measurement.

## Positive control

`measure/test-control.sh` ties runs 4, 5, 6 and 7 on the c48 box to their saved chip reports. For each
run it:
1. verifies the report's signature offline with this repository's own verifier
   (`tee/web/snp-verify.js`, through `measure/verify-report.mjs`): the AMD Genoa root pinned by hash,
   the ASK, the run's VCEK, then the report's ECDSA P-384 signature. The policy must be 0x30000. Needs
   node 22 or newer. REPORT_DATA binding is not checked; it is per box and not part of the measurement;
2. checks that the MEASUREMENT of that verified report equals the value the notes recorded (run 4: the
   12 character prefix the notes name; runs 5, 6, 7: `measurement.expected`);
3. recomputes the fingerprint from the saved firmware, kernel, initrd and command line, and requires
   it to equal the verified report's MEASUREMENT.

It also shows that another `--guest-features` or `--vmm-type` value does not match, so neither can
fall back to a default silently.

The bundle (every file the control reads, about 37 MB: the c48 boot artifacts, the image 4 verity
line, and the four runs' reports, VCEKs, command lines and recorded values) is not in this repository.
It lives in the notes folder `~/Documents/INBOX/blueprint2-tee-20261104/` on Fred's Mac; ask Fred for
a copy. `CATHEDRAL_CONTROL_DIR` names the folder, laid out like those notes. `measure/control-inputs.sha256`
lists the sha256 of each file, and the control checks the bundle against it first, so a second person
knows they hold the same bytes. Unset, the control prints SKIP and exits 0. A mismatch exits 1.

Result on a Mac with `sev-snp-measure` 0.0.13: for all four runs the report signature verifies, the
notes value equals it, and the computed fingerprint equals it. Version 0.0.12 gives the same four
values; 0.0.13 is pinned because the c48 notes used it.

## What is and is not in this repository

- Here: the manifest format, the fingerprint and check scripts, the unit tests, and the control.
- Not here yet: a reproducible build of the rootfs, kernel, initrd or firmware. The kernel (`62a3...`)
  was built twice on one host (c48) with identical output, but no recipe is in this repository. The
  kernel, initrd and firmware are copies of files from c48 or from an Ubuntu package. Their build recipes
  (pinned tarball hash, builder toolchain, initrd base, firmware package hash) are the next step, and a
  kernel rebuilt elsewhere may differ byte for byte. This repository's rootfs script does not pin a
  snapshot or a build date either.
- What a passing check proves: the arithmetic from these input files to this number, and that for runs
  4 to 7 the number is the one the chip signed. It does not prove the files were built from source, and
  it does not prove a new box reports the number; that needs an AMD host.

## Finding: the initrd holds more than it should

Unpacking `initrd-desktop.gz`:
- `bin/busybox`: static, BusyBox 1.37.0 from Ubuntu `1:1.37.0-7ubuntu1`.
- `bin/boxd`: a 5 MB Go binary built with Go 1.27.3. Its sha256 (`826ab41a...`) is not the rootfs
  boxd (`40710dac...`), and `tee/boxd` is not its source. The init never runs it.
- `lib/modules/sev-guest.ko` and `tsm_report.ko`, vermagic `7.0.0-34-generic`. The custom kernel has
  both drivers built in, so `insmod` fails and the init discards the error (`2>/dev/null`). They do
  nothing.

Recipe for the next step: keep only `bin/busybox`, the empty `dev proc sys`, and `init`. Drop `boxd`,
both `.ko` files and the two `insmod` lines. A measured file must not carry a binary of unknown
source. This changes the initrd hash, which is fine since the kernel hash will change too
(`CONFIG_FW_CFG_SYSFS` moves from `m` to `y` for the key driver).
