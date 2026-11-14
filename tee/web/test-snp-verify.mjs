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

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
