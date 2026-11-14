# What the TEE box promises today

The TEE box is a desktop inside an AMD SEV-SNP confidential machine, viewed through a sealed stream.
This page says which ways a session's bytes could reach someone else, which are closed, and what closes the
rest. `tee/test_wording.py` fails the build when README, the Markdown files under `tee/`, the page HTML or
the strings of the page JavaScript claim more than this page allows. It does not read code comments.

## Paths

| Path | Today | What closes it |
|---|---|---|
| P1 The host reads guest memory | Partly closed: the clients refuse debug and migration. No firmware floor is set. | Set the firmware floor value (D3). |
| P2 The host boots another image | Closed on QEMU with kernel hashes. Open on Cloud Hypervisor: the host picks the kernel, the initrd and the command line, and open pull request 8 says the default stage0 enforces none of them. | Pass the stage0 control in pull request 8, or sell QEMU only. |
| P3 Cathedral opens a stream with its ticket key | Open. | A customer key that opens the box instead (customer mode). |
| P4 A keyless image opens on an empty ticket | Open. | The customer image holds no key and refuses an empty ticket. |
| P5 The relay or the network reads frames | Closed. They still see sizes, timing and the report. | Not needed. |
| P6 Whoever serves the viewer page | Open. The relay serves it. | A viewer page from the customer's own disk. The hosted page shows who serves it. |
| P7 Who picks the trusted build | Open. The fingerprint comes from the link. There is no published list. | A list the client pins, and a published list. |
| P8 The ticket reaches URL logs | Closed. The ticket travels in the fragment. | Done. |
| P9 Other listeners in the box | Closed only because websockify is not installed. There is no firewall in the box. | A firewall that allows the two stream ports only. |
| P10 Storage and snapshots | Closed. The root is read-only and the work lives in memory. | Not needed. |
| P11 Console and debug access | Closed for content. The serial port takes HALT only. | Not needed. |
| P12 Cathedral logs, metrics and support tools | Nothing in `tee/` sends data except AMD key fetches. The mint API is not built. | Check the mint API when it is built. |
| P13 The box's own outbound traffic | Open. The host sees the names it looks up and the sites it connects to. | Not planned. |
| P14 The image build channel | Open. The repository is private and the build recipes are not in it. | Publish the source and the recipes, and a second-host build. |
| P15 The client build channel | Open until the noVNC download is pinned by sha256. | Pin the version and its hash, and refuse any other. |
| P16 Keys | The box keys are fresh at every boot. The ticket key is Cathedral's. There is no customer key. | Customer mode. |
| P17 Uploaded code run under a ticket | Open in draft pull request 11. | Allow it only in customer mode. |

## Allowed sentences

- S1 The TEE box runs inside an AMD SEV-SNP confidential machine. The chip encrypts its memory.
- S2 Before the client sends its ticket or anything you type, it checks the box's attestation report: the AMD certificate chain, the report's signature, the build fingerprint against the list the client is given, and that the machine does not allow debugging or migration. A link can waive the build list; the page then shows ANY BUILD ACCEPTED.
- S3 If a check fails, the page stops and says which one.
- S4 The client encrypts to a key that only the checked box holds. Relays and the network carry encrypted frames. They see sizes, timing and the box's report: chip id, build fingerprint, firmware level.
- S5 The box has no disk it can write to. Its work lives in encrypted memory and is gone when it stops.
- S6 Today Cathedral holds the key that opens a box, so Cathedral can see its screen.
- S7 Whoever serves the viewer page can see the screen it shows. Today the relay that carries the stream also serves the page.
- S8 The host can stop the box, cut the stream, see the names the box looks up and the sites it connects to, and read anything it sends unencrypted.
- S9 Reports are vouched for by the AMD chip.

S3 is limited to the page. The Python client does not yet name each failed signature check.

## Not allowed

- "No one can see inside", "not even Cathedral", "Cathedral cannot see": not until all of these hold. Customer mode is live in a listed build. A local client checks it. A firmware floor is set (D3). Others can rebuild that build.
- Any "proof", "proves", "prove" or "provable" about the product.
- "Cathedral-signed". The AMD chip vouches for reports (S9).
- "Anyone can rebuild": not before the second-host build passes.
- "The host cannot change the software": not until P2 is closed.
- "End-to-end encrypted so only you can see."
- "Unavailable" for a busy sealed pool. Say "sold out".
