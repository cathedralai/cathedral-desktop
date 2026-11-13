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
python3 -I -m unittest discover -s tee/build/measure                    # no inputs needed
```

`check.sh` fails (exit 1) unless all three hold:
1. the installed `sev-snp-measure` is the version the manifest pins;
2. the sha256 of the firmware, kernel and initrd in `INPUTS_DIR` equals the manifest's;
3. the computed fingerprint equals the manifest's, for every vCPU count the manifest lists.

`manifests/run5-example.manifest.json` describes run 5 (hashes and parameters only, no binaries).
Its files are the ones named under `inputs`; put them in one folder and pass that folder.

## Manifest

Shape in `manifest.schema.json`, enforced by `measure/manifest.py`. It holds the three input files by
hash, the exact kernel command line (which carries the dm-verity root hash), the CPU model, and one
expected fingerprint per vCPU count.

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

`measure/test-control.sh` recomputes runs 4, 5, 6 and 7 from the saved c48 inputs and compares each
with the value recorded in the notes. It needs the control folder (about 40 MB, not in this
repository) named in `CATHEDRAL_CONTROL_DIR`, laid out like the blueprint2-tee notes. Unset, it prints
SKIP and exits 0. A mismatch exits 1. Run 5 is also compared with the MEASUREMENT (offset 0x90) of
its saved chip-signed report; run 4 takes its recorded value from its saved report. Runs 6 and 7
have only values computed on c48, no chip report.

Result on a Mac with `sev-snp-measure` 0.0.13: all four match, and run 5's chip report equals the
computed value. Version 0.0.12 gives the same four values; 0.0.13 is pinned because the c48
notes used it.

## What is and is not reproducible yet

- Measured and checked here: a published fingerprint can be recomputed from the three input files,
  the command line and the launch parameters.
- Not yet reproducible: the kernel, the initrd and the firmware are copies of files from c48 or
  from an Ubuntu package. Their build recipes (pinned tarball hash, builder toolchain, initrd base,
  firmware package hash) are the next step. A kernel rebuilt elsewhere may differ byte for byte.
- The rootfs build (`tee/rootfs`) is reproducible on one host so far; a second host is untested.
- A passing check proves the arithmetic from these files to this number. It does not prove the files
  were built from source, and it does not prove a running box reports the number; that needs an
  AMD host.

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
