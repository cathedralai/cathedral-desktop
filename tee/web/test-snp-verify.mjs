// node tee/web/test-snp-verify.mjs
// Checks the DER walker and the RSA-PSS chain against the AMD Genoa certificates in tee/fixtures.
// With tee/fixtures/report.bin, cert.der (box TLS cert) and vcek.der present (a real box run), it
// also checks the report signature and the AB#361 REPORT_DATA binding.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { verifyAmdChain, verifySnp, parseReport, parseCert, kdsVcekUrl, sha256, hex } from './snp-verify.js';

const fx = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (n) => new Uint8Array(readFileSync(join(fx, n)));
let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!ok) failures++; };

const ark = read('amd-genoa-ark.der');
const ask = read('amd-genoa-ask.der');

// 1. chain: pinned ARK, ARK self-signed, ASK by ARK
try {
  const r = await verifyAmdChain({ ark, ask }, 'Genoa');
  check('ARK pinned and self-signed, ASK signed by ARK', true, `ark pin ${r.arkPin.slice(0, 16)}`);
} catch (e) { check('ARK/ASK chain', false, e.message); }

// 2. negative: ASK presented as ARK must be refused by the pin
try { await verifyAmdChain({ ark: ask, ask }, 'Genoa'); check('wrong root refused', false); }
catch (e) { check('wrong root refused', /pinned/.test(e.message), e.message); }

// 3. negative: one flipped bit in the ASK signature
try {
  const bad = ask.slice(); bad[bad.length - 1] ^= 0x01;
  await verifyAmdChain({ ark, ask: bad }, 'Genoa'); check('tampered ASK refused', false);
} catch (e) { check('tampered ASK refused', /ASK/.test(e.message), e.message); }

// 4. a real box run, when the fixture exists
if (existsSync(join(fx, 'report.bin')) && existsSync(join(fx, 'vcek.der'))) {
  const report = read('report.bin');
  const vcek = read('vcek.der');
  const rep = parseReport(report);
  console.log(`report v${rep.version} chip ${rep.chipId.slice(0, 16)}… measurement ${rep.measurement.slice(0, 16)}… kds ${kdsVcekUrl(rep)}`);
  let binding;
  if (existsSync(join(fx, 'binding.json'))) {
    // REPORT_DATA = sha256(canonical binding) || zeros; the file holds those exact bytes.
    binding = { first: await sha256(new Uint8Array(readFileSync(join(fx, 'binding.json')))), second: null };
  } else if (existsSync(join(fx, 'cert.der'))) {
    console.log('note: no binding.json, checking the pre-binding layout sha256(TLS SPKI)||zeros');
    binding = { first: await sha256(parseCert(read('cert.der')).spki), second: null };
  }
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [], allowAnyMeasurement: true });
    check('real report: VCEK chain, signature, REPORT_DATA binding', r.ok, `measurement ${r.measurement.slice(0, 16)} testMode=${r.testMode}`);
  } catch (e) { check('real report', false, e.message); }
  // The chip certificate names its firmware in four AMD extensions (12, 0, 28, 88 for the saved chip);
  // they must equal the report's own numbers at 0x180, 0x181, 0x186, 0x187, and that check runs before the
  // report's signature, so a changed byte is named as a firmware mismatch.
  for (const [off, part] of [[0x180, 'bl'], [0x181, 'tee'], [0x186, 'snp'], [0x187, 'ucode']]) {
    try {
      const bad = report.slice(); bad[off] ^= 0x01;
      await verifySnp({ report: bad, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true }); check(`firmware byte ${part} changed: refused`, false, 'accepted');
    } catch (e) { check(`firmware byte ${part} changed: refused`, /firmware/i.test(e.message) && e.message.includes(part), e.message); }
  }
  // minTcb is a floor on the reported numbers, checked after the signature; parts left out are not checked.
  const tcb = { bl: report[0x180], tee: report[0x181], snp: report[0x186], ucode: report[0x187] };
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, minTcb: tcb });
    check('floor equal to the reported firmware: accepted', r.ok, JSON.stringify(tcb));
  } catch (e) { check('floor equal to the reported firmware', false, e.message); }
  for (const part of ['bl', 'tee', 'snp', 'ucode']) {
    try {
      await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, minTcb: { [part]: tcb[part] + 1 } });
      check(`floor one above the reported ${part}: refused`, false, 'accepted');
    } catch (e) { check(`floor one above the reported ${part}: refused`, /below the floor/i.test(e.message) && e.message.includes(part), e.message); }
  }
  // The floor is checked for shape before anything is compared: only the four part names, each an integer 0 to 255.
  // A part left out means no floor for that part (the other parts still apply).
  const meas = rep.measurement;
  for (const [label, floor] of [['an unknown key', { snp: 1, bogus: 1 }], ['NaN', { snp: NaN }], ['a negative', { snp: -1 }], ['a float', { snp: 1.5 }],
      ['a string', { snp: '5' }], ['over 255', { snp: 256 }], ['null', { snp: null }], ['an array', [1, 2, 3, 4]], ['a number', 5], ['a string instead of an object', 'snp']]) {
    try {
      await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, minTcb: floor }); check(`floor with ${label}: refused`, false, 'accepted');
    } catch (e) { check(`floor with ${label}: refused`, /^invalid TCB floor/.test(e.message), e.message); }
  }
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, minTcb: { snp: 28 } });
    check('floor with one part only: the others are not checked', r.ok);
    const e = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, minTcb: {} });
    check('an empty floor object is no floor', e.ok);
  } catch (e) { check('partial floor', false, e.message); }

  // Fingerprints: trimmed and lower-cased, then exactly 96 hex characters; anything else is refused up front.
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [`  ${meas.toUpperCase()}\n`] });
    check('an upper-case, padded fingerprint is accepted', r.ok && r.testMode === false);
  } catch (e) { check('an upper-case, padded fingerprint is accepted', false, e.message); }
  for (const [label, bad] of [['too short', meas.slice(0, 94)], ['too long', meas + '00'], ['not hex', 'zz' + meas.slice(2)], ['empty', '']]) {
    try {
      await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [meas, bad] }); check(`fingerprint ${label}: refused`, false, 'accepted');
    } catch (e) { check(`fingerprint ${label}: refused`, /^invalid fingerprint/.test(e.message), e.message); }
  }
  // No fingerprint list is a refusal unless the caller says, in words, that any build will do.
  for (const [label, extra] of [['no list', {}], ['empty list', { allowedMeasurements: [] }], ['allowAnyMeasurement false', { allowAnyMeasurement: false }]]) {
    try {
      await verifySnp({ report, certs: { ark, ask, vcek }, binding, ...extra }); check(`${label}: refused`, false, 'accepted');
    } catch (e) { check(`${label}: refused`, /fingerprint/i.test(e.message), e.message); }
  }
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true });
    check('allowAnyMeasurement: accepted and still reported as test mode', r.ok && r.testMode === true, `testMode=${r.testMode}`);
  } catch (e) { check('allowAnyMeasurement', false, e.message); }
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowAnyMeasurement: true, allowedMeasurements: [rep.measurement] });
    check('a list wins over the waiver: not test mode', r.ok && r.testMode === false);
  } catch (e) { check('list with waiver', false, e.message); }
  try {
    const bad = report.slice(); bad[0x90] ^= 0x01;
    await verifySnp({ report: bad, certs: { ark, ask, vcek }, binding }); check('tampered measurement refused', false);
  } catch (e) { check('tampered measurement refused', /signature/.test(e.message), e.message); }
  // Policy bits are signed, so a flipped bit also breaks the signature; the policy refusal has to come
  // first for the message to name the policy. bit 19 = debug (byte 10, 0x08), bit 18 = migration (byte 10, 0x04).
  for (const [bit, word, re] of [[0x08, 'debug', /debug/i], [0x04, 'migration', /migration/i]]) {
    try {
      const bad = report.slice(); bad[10] |= bit;
      await verifySnp({ report: bad, certs: { ark, ask, vcek }, binding }); check(`${word} policy bit refused`, false);
    } catch (e) { check(`${word} policy bit refused`, re.test(e.message), e.message); }
  }
  check('saved report policy has neither bit', (report[10] & 0x0c) === 0, `policy ${rep.policy}`);
  // The fingerprint pin: the viewer passes fp= and an unlisted image must not render.
  try {
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [rep.measurement] });
    check('this measurement pinned: accepted, not test mode', r.ok && r.testMode === false, `testMode=${r.testMode}`);
  } catch (e) { check('this measurement pinned', false, e.message); }
  try {
    const other = 'ff' + rep.measurement.slice(2);
    await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [other] });
    check('another measurement pinned: refused', false);
  } catch (e) { check('another measurement pinned: refused', /measurement/i.test(e.message), e.message); }
} else {
  console.log('skip real report checks: tee/fixtures/report.bin and vcek.der not present yet');
}

// ---- customer mode (AB#353 WP2): the report's HOST_DATA must equal sha256("cathedral-tee-customer/v1\0" || customer key).
// Namespace import so a missing export fails its own check instead of the whole file.
const sv = await import('./snp-verify.js');
const vec = JSON.parse(readFileSync(join(fx, '..', 'testdata', 'customer_host_data_v1.json'), 'utf8'));
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const kPub = unhex(vec.customer.public_key_hex);
const b64uOf = (u8) => Buffer.from(u8).toString('base64url');
const fails = async (name, fn, re) => {
  try { await fn(); check(name, false, 'accepted'); } catch (e) { check(name, re.test(e.message), e.message); }
};

// The shared vector: same file as the Python test; JS rebuilds it from the key.
try {
  check('vector: preimage is domain, zero byte, key', vec.customer.preimage_hex === vec.domain_hex + vec.customer.public_key_hex && vec.domain_hex.endsWith('00'));
  check('vector: JS rebuilds HOST_DATA from the key', hex(await sv.customerHostData(kPub)) === vec.customer.host_data_hex, hex(await sv.customerHostData(kPub)));
  check('vector: file value is sha256 of the stored preimage', hex(await sha256(unhex(vec.customer.preimage_hex))) === vec.customer.host_data_hex);
  check('vector: a different key gives the other stored value', hex(await sv.customerHostData(unhex(vec.other_customer.public_key_hex))) === vec.other_customer.host_data_hex);
  check('vector: the domain without its trailing zero byte gives a different value', vec.without_trailing_zero.host_data_hex !== vec.customer.host_data_hex
    && hex(await sha256(unhex(vec.without_trailing_zero.preimage_hex))) === vec.without_trailing_zero.host_data_hex);
  check('vector: the stored unlabelled sha256(key) differs and is what sha256 of the bare key gives', vec.unlabelled_sha256_of_key.host_data_hex !== vec.customer.host_data_hex
    && hex(await sha256(kPub)) === vec.unlabelled_sha256_of_key.host_data_hex);
  check('vector: the stored b64url form decodes to the stored key', hex(sv.parseCustomerKey(vec.customer.public_key_b64u)) === vec.customer.public_key_hex);
} catch (e) { check('vector', false, e.message); }

// The pure check: checkCustomerHostData(hostData bytes, customer public key bytes). A check that only tests "not zero" fails the cases below.
{
  const good = unhex(vec.customer.host_data_hex);
  const chk = (hd, pub = kPub) => sv.checkCustomerHostData(hd, pub);
  try { await chk(good); check('check: HOST_DATA for this key is accepted', true); } catch (e) { check('check: HOST_DATA for this key is accepted', false, e.message); }
  await fails('check: HOST_DATA for a different customer key is refused', () => chk(unhex(vec.other_customer.host_data_hex)), /HOST_DATA.*(different|does not match)/i);
  await fails('check: all-zero HOST_DATA is refused as zero', () => chk(new Uint8Array(32)), /HOST_DATA.*zero/i);
  await fails('check: sha256(key) without the label is refused', () => chk(unhex(vec.unlabelled_sha256_of_key.host_data_hex)), /HOST_DATA.*(different|does not match)/i);
  await fails('check: the value built without the trailing zero byte is refused', () => chk(unhex(vec.without_trailing_zero.host_data_hex)), /HOST_DATA.*(different|does not match)/i);
  await fails('check: a 31-byte HOST_DATA is refused', () => chk(good.slice(0, 31)), /HOST_DATA/);
  await fails('check: a 33-byte HOST_DATA is refused', () => chk(new Uint8Array([...good, 0])), /HOST_DATA/);
  await fails('check: a 31-byte customer key is a usage error', () => chk(good, kPub.slice(0, 31)), /^invalid customer key/);
  let all = true;
  for (let i = 0; i < 32; i++) for (const bit of [0x01, 0x80]) {
    const h = good.slice(); h[i] ^= bit;
    try { await chk(h); all = false; } catch { /* refused */ }
  }
  check('check: comparison is exact, a one-bit change in any of the 32 bytes is refused', all);
}

{
  const rBytes = read('report.bin');
  const rb = { first: await sha256(new Uint8Array(readFileSync(join(fx, 'binding.json')))), second: null };
  const base = { report: rBytes, certs: { ark, ask, vcek: read('vcek.der') }, binding: rb };
  const meas = parseReport(rBytes).measurement;
  const listed = { allowedMeasurements: [meas] };
  const withHostData = (hex32) => { const b = rBytes.slice(); b.set(unhex(hex32), 0xC0); return b; };
  const key = vec.customer.public_key_b64u;

  check('saved report HOST_DATA is all zero (today\'s fixture)', parseReport(rBytes).hostData === '00'.repeat(32));
  await fails('customer key set, HOST_DATA zero: refused, names HOST_DATA and zero', () => verifySnp({ ...base, ...listed, customerKey: key }), /HOST_DATA.*zero/i);
  // Right value in the report but the bytes are no longer the ones the chip signed: every earlier check still runs.
  await fails('customer key set, right HOST_DATA in an unsigned edit: the signature check still refuses', () => verifySnp({ ...base, report: withHostData(vec.customer.host_data_hex), ...listed, customerKey: key }), /signature/);
  await fails('customer key set, a wrong measurement is refused before HOST_DATA is looked at', () => verifySnp({ ...base, allowedMeasurements: ['ff'.repeat(48)], customerKey: key }), /not an allowed fingerprint/);

  // Customer mode refuses every waiver: the host picks HOST_DATA freely, so it binds the key only with the build checked too.
  await fails('customer key set + allowAnyMeasurement: refused by name', () => verifySnp({ ...base, allowAnyMeasurement: true, customerKey: key }), /customer mode.*allowAnyMeasurement/i);
  await fails('customer key set + allowAnyMeasurement + a list: still refused', () => verifySnp({ ...base, ...listed, allowAnyMeasurement: true, customerKey: key }), /customer mode.*allowAnyMeasurement/i);
  await fails('customer key set + empty fingerprint list: refused by name', () => verifySnp({ ...base, allowedMeasurements: [], customerKey: key }), /customer mode.*fingerprint list/i);
  await fails('customer key set + no fingerprint list: refused by name', () => verifySnp({ ...base, customerKey: key }), /customer mode.*fingerprint list/i);
  await fails('customer key set + allowDev: refused by name', () => verifySnp({ ...base, ...listed, allowDev: true, customerKey: key }), /customer mode.*allowDev/i);

  // Input shape: a usage error before anything else, never a silent "no customer mode".
  const shapes = [['empty string', ''], ['null', null], ['not base64url', '!'.repeat(43)], ['standard base64 characters', key.replace(/-/g, '+').replace(/_/g, '/') + '/'],
    ['padded', key + '='], ['31 bytes', b64uOf(kPub.slice(0, 31))], ['33 bytes', b64uOf(new Uint8Array([...kPub, 0]))], ['a number', 5], ['a byte array', kPub], ['non-canonical trailing bits', key.slice(0, 42) + 'B']];
  for (const [label, bad] of shapes) {
    await fails(`customer key ${label}: usage error`, () => verifySnp({ ...base, ...listed, customerKey: bad }), /^invalid customer key/);
  }
  // Off by default: undefined is the only way to leave it off, and the result is what main returns.
  try {
    const off = await verifySnp({ ...base, allowAnyMeasurement: true });
    const undef = await verifySnp({ ...base, allowAnyMeasurement: true, customerKey: undefined });
    check('no customer key: same result as before, including fixtures with zero HOST_DATA and the waiver', off.ok && JSON.stringify(off) === JSON.stringify(undef) && !('customer' in off) && !('hostData' in off), Object.keys(off).join(','));
    const pinned = await verifySnp({ ...base, ...listed });
    check('no customer key: pinned fingerprint still accepted', pinned.ok && pinned.testMode === false);
  } catch (e) { check('no customer key: same result as before', false, e.message); }
}

// ---- review fixes (AB#353): weak customer keys, ticket under the customer key, HOST_DATA offset.
{
  const weak = [...vec.weak_keys.small_order_hex, ...vec.weak_keys.non_canonical_hex];
  check('vector: 8 small-order encodings are listed', vec.weak_keys.small_order_hex.length === 8);
  for (const h of weak) {
    const k = b64uOf(unhex(h));
    await fails(`weak customer key ${h.slice(0, 8)}..${h.slice(-4)}: usage error`, () => sv.parseCustomerKey(k), /^invalid customer key/);
    await fails(`weak customer key ${h.slice(0, 8)}..${h.slice(-4)}: verifySnp refuses it before anything else`, () => verifySnp({ report: read('report.bin'), certs: { ark, ask, vcek: read('vcek.der') }, binding: null, allowedMeasurements: ['ab'.repeat(48)], customerKey: k }), /^invalid customer key/);
    await fails(`weak customer key ${h.slice(0, 8)}..${h.slice(-4)}: the pure check refuses it`, () => sv.checkCustomerHostData(unhex(vec.customer.host_data_hex), unhex(h)), /^invalid customer key/);
  }
  try { sv.parseCustomerKey(vec.customer.public_key_b64u); check('a real customer key is still accepted', true); } catch (e) { check('a real customer key is still accepted', false, e.message); }

  // HOST_DATA is bytes 0xC0 to 0xDF. A synthetic buffer whose neighbours differ, so a wrong offset cannot pass.
  const buf = new Uint8Array(sv.REPORT_LEN);
  buf.fill(0x11, 0xA0, 0xC0); buf.fill(0x22, 0xC0, 0xE0); buf.fill(0x33, 0xE0, 0x100);
  try {
    check('reportHostData reads bytes 0xC0 to 0xDF', hex(sv.reportHostData(buf)) === '22'.repeat(32), hex(sv.reportHostData(buf)));
    check('parseReport reports the same HOST_DATA', parseReport(buf).hostData === '22'.repeat(32));
  } catch (e) { check('reportHostData', false, e.message); }

  // The ticket the client sends in customer mode: present, and signed by the customer key.
  const kp = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const kpOther = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const rawPub = new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', kp.publicKey));
  const mk = async (pair, body = '{"box":"x","target":"vnc"}') => {
    const bb = new TextEncoder().encode(body);
    const sig = new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', pair.privateKey, bb));
    return `${b64uOf(bb)}.${b64uOf(sig)}`;
  };
  try { await sv.checkCustomerTicket(await mk(kp), rawPub); check('ticket signed by the customer key is accepted', true); } catch (e) { check('ticket signed by the customer key is accepted', false, e.message); }
  await fails('empty ticket in customer mode: refused by name', () => sv.checkCustomerTicket('', rawPub), /customer mode needs a ticket/);
  await fails('ticket signed by another key: usage error', async () => sv.checkCustomerTicket(await mk(kpOther), rawPub), /customer mode.*signed by the customer key/);
  await fails('ticket with a changed body: refused', async () => { const t = await mk(kp); await sv.checkCustomerTicket(`${b64uOf(new TextEncoder().encode('{"box":"y"}'))}.${t.split('.')[1]}`, rawPub); }, /signed by the customer key/);
  for (const bad of ['abc', 'a.b.c', '!!.??', 'AAAA.AAAA']) await fails(`malformed ticket ${JSON.stringify(bad)}: refused`, () => sv.checkCustomerTicket(bad, rawPub), /customer mode/);
}

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
