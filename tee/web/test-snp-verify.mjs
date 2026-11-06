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
    const r = await verifySnp({ report, certs: { ark, ask, vcek }, binding, allowedMeasurements: [] });
    check('real report: VCEK chain, signature, REPORT_DATA binding', r.ok, `measurement ${r.measurement.slice(0, 16)} testMode=${r.testMode}`);
  } catch (e) { check('real report', false, e.message); }
  try {
    const bad = report.slice(); bad[0x90] ^= 0x01;
    await verifySnp({ report: bad, certs: { ark, ask, vcek }, binding }); check('tampered measurement refused', false);
  } catch (e) { check('tampered measurement refused', /signature/.test(e.message), e.message); }
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
