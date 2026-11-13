// AMD SEV-SNP attestation report verification with WebCrypto only.
// Runs in browsers and in Node 20+ (globalThis.crypto.subtle). No dependencies.
//
// Checks, in order: the ARK is the pinned AMD root; ARK signs itself, ASK, and ASK signs the VCEK
// (RSA-PSS SHA-384, salt 48); the VCEK (ECDSA P-384) signs the report; REPORT_DATA binds the key
// the box presented; MEASUREMENT is one the caller allows. Offsets follow the SNP ABI (report
// version 2 and 3, 1184 bytes), the same ones kit/snpverify.py uses.

const subtle = globalThis.crypto.subtle;

/** sha256 of the ARK certificate DER from https://kdsintf.amd.com/vcek/v1/<product>/cert_chain: the same
 *  pin ctcli, go-sev-guest and virtee/sev use (tee/fixtures/amd-genoa-ark.der, checked 6 Nov 2026). */
export const AMD_ARK_SHA256 = {
  Genoa: '4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1',
  Milan: '69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd',
};

export const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (s) => Uint8Array.from(s.match(/.{2}/g) || [], (h) => parseInt(h, 16));
export async function sha256(bytes) { return new Uint8Array(await subtle.digest('SHA-256', bytes)); }
export function equal(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---- minimal DER walking (enough for X.509 v3 certificates)

function tlv(b, off) {
  if (off + 2 > b.length) throw new Error('DER: truncated');
  const tag = b[off];
  let len = b[off + 1];
  let p = off + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error('DER: bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[p++];
  }
  if (p + len > b.length) throw new Error('DER: length past end');
  return { tag, hdr: off, start: p, end: p + len };
}

function seq(b, node) {
  const out = [];
  let p = node.start;
  while (p < node.end) { const c = tlv(b, p); out.push(c); p = c.end; }
  return out;
}

const slice = (b, node, withHeader = true) => b.slice(withHeader ? node.hdr : node.start, node.end);

function oidString(b, node) {
  const arc = [];
  let v = 0;
  for (let p = node.start; p < node.end; p++) {
    v = v * 128 + (b[p] & 0x7f);
    if (!(b[p] & 0x80)) { arc.push(v); v = 0; }
  }
  const first = arc.shift();
  return [Math.min(Math.floor(first / 40), 2), first - 40 * Math.min(Math.floor(first / 40), 2), ...arc].join('.');
}

// AMD's chip certificate carries the firmware numbers it was issued for in these extensions
// (the part names are the ones the KDS URL uses): each value is an OCTET STRING holding a DER INTEGER.
const AMD_TCB_OIDS = { '1.3.6.1.4.1.3704.1.3.1': 'bl', '1.3.6.1.4.1.3704.1.3.2': 'tee', '1.3.6.1.4.1.3704.1.3.3': 'snp', '1.3.6.1.4.1.3704.1.3.8': 'ucode' };

function amdTcbExtensions(b, fields) {
  const out = {};
  const wrapper = fields.find((f) => f.tag === 0xa3); // [3] EXPLICIT extensions
  if (!wrapper) return out;
  for (const ext of seq(b, seq(b, wrapper)[0])) {
    const [oid, ...rest] = seq(b, ext);
    const part = AMD_TCB_OIDS[oidString(b, oid)];
    if (!part) continue;
    const value = rest[rest.length - 1]; // the OCTET STRING; a critical flag, when present, sits before it
    const num = tlv(b, value.start);
    if (num.tag !== 0x02 || num.end - num.start < 1 || num.end - num.start > 2) throw new Error('DER: unexpected firmware number');
    out[part] = num.end - num.start === 1 ? b[num.start] : b[num.start] * 256 + b[num.start + 1];
  }
  return out;
}

/** Split a DER certificate into the parts verification needs. */
export function parseCert(der) {
  const b = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = tlv(b, 0);
  if (cert.tag !== 0x30) throw new Error('DER: certificate is not a SEQUENCE');
  const [tbs, , sigVal] = seq(b, cert);
  const fields = seq(b, tbs);
  const i = fields[0].tag === 0xa0 ? 1 : 0; // explicit version present
  if (fields.length < i + 6) throw new Error('DER: tbsCertificate too short');
  return {
    tbs: slice(b, tbs),
    issuer: slice(b, fields[i + 2]),
    subject: slice(b, fields[i + 4]),
    spki: slice(b, fields[i + 5]),
    signature: b.slice(sigVal.start + 1, sigVal.end), // BIT STRING: skip the unused-bits byte
    amdTcb: amdTcbExtensions(b, fields.slice(i + 6)),
  };
}

async function rsaPssVerify(signerSpki, signature, data) {
  const key = await subtle.importKey('spki', signerSpki, { name: 'RSA-PSS', hash: 'SHA-384' }, false, ['verify']);
  return subtle.verify({ name: 'RSA-PSS', saltLength: 48 }, key, signature, data);
}

/** Verify ARK (pinned, self-signed) -> ASK -> VCEK. `vcek` may be omitted to check only the AMD pair. */
export async function verifyAmdChain({ ark, ask, vcek }, product = 'Genoa') {
  const A = parseCert(ark);
  const S = parseCert(ask);
  const pin = hex(await sha256(ark instanceof Uint8Array ? ark : new Uint8Array(ark)));
  if (pin !== AMD_ARK_SHA256[product]) throw new Error(`ARK is not the pinned AMD ${product} root (${pin.slice(0, 12)})`);
  if (!(await rsaPssVerify(A.spki, A.signature, A.tbs))) throw new Error('ARK self-signature failed');
  if (!(await rsaPssVerify(A.spki, S.signature, S.tbs))) throw new Error('ASK is not signed by the ARK');
  if (!vcek) return { arkPin: pin, askSpki: S.spki, vcekSpki: null, vcekTcb: null };
  const V = parseCert(vcek);
  if (!(await rsaPssVerify(S.spki, V.signature, V.tbs))) throw new Error('VCEK is not signed by the ASK');
  return { arkPin: pin, askSpki: S.spki, vcekSpki: V.spki, vcekTcb: V.amdTcb };
}

// ---- the report

export const REPORT_LEN = 0x2A0 + 144;

export function parseReport(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (b.length < REPORT_LEN) throw new Error(`report is ${b.length} bytes, expected at least ${REPORT_LEN}`);
  const u32 = (o) => b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
  return {
    version: u32(0),
    guestSvn: u32(4),
    policy: hex(b.slice(8, 16).reverse()),
    vmpl: u32(0x30),
    reportData: b.slice(0x50, 0x90),
    measurement: hex(b.slice(0x90, 0xC0)),
    hostData: hex(b.slice(0xC0, 0xE0)),
    reportId: hex(b.slice(0x140, 0x160)),
    reportedTcb: b.slice(0x180, 0x188),
    chipId: hex(b.slice(0x1A0, 0x1E0)),
    signed: b.slice(0, 0x2A0),
    r: b.slice(0x2A0, 0x2A0 + 72),
    s: b.slice(0x2E8, 0x2E8 + 72),
  };
}

/** Where AMD KDS serves the VCEK for this chip at this TCB (cache it; KDS rate-limits). */
export function kdsVcekUrl(report, product = 'Genoa') {
  const t = report.reportedTcb;
  return `https://kdsintf.amd.com/vcek/v1/${product}/${report.chipId}?blSPL=${t[0]}&teeSPL=${t[1]}&snpSPL=${t[6]}&ucodeSPL=${t[7]}`;
}

function leToBe(le, n) {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[n - 1 - i] = le[i];
  return out;
}

export async function verifyReportSignature(report, vcekSpki) {
  const key = await subtle.importKey('spki', vcekSpki, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
  const raw = new Uint8Array(96);
  raw.set(leToBe(report.r, 48), 0);
  raw.set(leToBe(report.s, 48), 48);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, raw, report.signed);
}

/**
 * Full check. `binding` says what REPORT_DATA must equal: { first: 32 bytes, second: 32 bytes | null }
 * (null = must be zero; AB#361 boxes put sha256(TLS SPKI) first and zeros second). `allowedMeasurements`
 * is a list of 96-hex strings. An empty list is refused unless `allowAnyMeasurement` is true, which the caller sets
 * only to learn a build's fingerprint; the result then says testMode, not a pass. `minTcb` is an optional
 * floor on the reported firmware, `{ bl, tee, snp, ucode }`, any part may be left out.
 */
export async function verifySnp({ report, certs, product = 'Genoa', binding, allowedMeasurements = [], allowAnyMeasurement = false, minTcb }) {
  const rep = parseReport(report);
  // Before any signature work: a guest that allows debugging or migration can be read or moved by the
  // host, so no later check makes its report worth trusting. Policy is 8 bytes little-endian at offset 8.
  const policyBit = (n) => (rep.signed[8 + (n >> 3)] >> (n & 7)) & 1;
  if (policyBit(19)) throw new Error('policy allows debugging (bit 19): the host can read this guest');
  if (policyBit(18)) throw new Error('policy allows migration (bit 18): the host can move this guest');
  const chain = await verifyAmdChain(certs, product);
  if (!chain.vcekSpki) throw new Error('VCEK missing');
  // The certificate was issued for one firmware level; the report must say the same, or the chip that
  // signed it is not the one the certificate vouches for. Before the signature so the message names it.
  const reported = { bl: rep.reportedTcb[0], tee: rep.reportedTcb[1], snp: rep.reportedTcb[6], ucode: rep.reportedTcb[7] };
  for (const part of ['bl', 'tee', 'snp', 'ucode']) {
    if (chain.vcekTcb[part] === undefined) throw new Error(`chip certificate has no firmware number for ${part}`);
    if (chain.vcekTcb[part] !== reported[part]) throw new Error(`firmware ${part} in the chip certificate (${chain.vcekTcb[part]}) does not match the report (${reported[part]})`);
  }
  if (!(await verifyReportSignature(rep, chain.vcekSpki))) throw new Error('report signature does not verify with the VCEK');
  // A floor, not a pin: the caller names the oldest firmware it will run on, per part; unset parts are not checked.
  for (const part of ['bl', 'tee', 'snp', 'ucode']) {
    if (minTcb?.[part] !== undefined && reported[part] < minTcb[part]) throw new Error(`reported firmware is below the floor: ${part} ${reported[part]} < ${minTcb[part]}`);
  }
  if (binding) {
    const want = new Uint8Array(64);
    want.set(binding.first, 0);
    if (binding.second) want.set(binding.second, 32);
    if (!equal(rep.reportData, want)) throw new Error('REPORT_DATA does not bind the presented key');
  }
  const measured = allowedMeasurements.length > 0;
  // Without a list the report proves a genuine chip, not that it runs our image, so a missing list must be a decision.
  if (!measured && !allowAnyMeasurement) throw new Error('no fingerprint list given: refusing to accept any build without allowAnyMeasurement');
  if (measured && !allowedMeasurements.includes(rep.measurement)) throw new Error(`MEASUREMENT ${rep.measurement.slice(0, 16)} is not an allowed fingerprint`);
  return {
    ok: true,
    testMode: !measured,
    version: rep.version,
    measurement: rep.measurement,
    chipId: rep.chipId,
    reportedTcb: hex(rep.reportedTcb),
    policy: rep.policy,
    tcb: reported,
    arkPin: chain.arkPin,
  };
}
