// node tee/web/test-stream-verify.mjs
// SealedStream.open hands the caller's verification options on to the report verifier. A fake box sends the
// saved chip report as its first frame; each case checks whether the open is refused or gets as far as
// "attested", which is where the real handshake would begin. No network and no boxd.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { SealedStream } from './sealed-stream.js';

const fx = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const read = (n) => new Uint8Array(readFileSync(join(fx, n)));
let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!ok) failures++; };

const report = read('report.bin');
const bindingText = new TextDecoder().decode(read('binding.json'));
const staticKey = Uint8Array.from(atob(JSON.parse(bindingText).sealed_stream.x25519_public_b64), (c) => c.charCodeAt(0));
const certs = { ark: read('amd-genoa-ark.der'), ask: read('amd-genoa-ask.der'), vcek: read('vcek.der') };
const measurement = Array.from(report.slice(0x90, 0xc0), (b) => b.toString(16).padStart(2, '0')).join('');
const enc = (b) => btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const frame = (obj) => { const body = new TextEncoder().encode(JSON.stringify(obj)); const out = new Uint8Array(4 + body.length); new DataView(out.buffer).setUint32(0, body.length); out.set(body, 4); return out; };

// Resolves with { status } when the open reaches "attested", or { error } when it is refused. The fake box says
// nothing after its first frame, so an open that got past verification is closed from the status callback.
async function tryOpen(verify) {
  const pipe = { onbytes: null, onclose: null, close() { this.onclose?.(); }, ready: Promise.resolve(),
    send() { queueMicrotask(() => this.onbytes?.(frame({ static: enc(staticKey), report: enc(report), binding: bindingText }))); } };
  let status = null;
  try {
    await SealedStream.open({ pipe, target: 'job', verify: { certs, ...verify }, onstatus: (m) => { if (m.startsWith('attested')) { status = m; pipe.close(); } } });
  } catch (e) {
    return status ? { status } : { error: e.message };
  }
  return { status };
}

let r = await tryOpen({ allowedMeasurements: [measurement] });
check('a listed fingerprint reaches attested, not marked as any build', !!r.status && !/any build/.test(r.status), JSON.stringify(r));

r = await tryOpen({});
check('no list and no waiver: refused', /no fingerprint list/.test(r.error || ''), JSON.stringify(r));

r = await tryOpen({ allowAnyMeasurement: true });
check('the explicit waiver reaches attested and says any build was accepted', /any build accepted/.test(r.status || ''), JSON.stringify(r));

r = await tryOpen({ allowAnyMeasurement: 'yes' });
check('only the value true is a waiver', /no fingerprint list/.test(r.error || ''), JSON.stringify(r));

r = await tryOpen({ allowAnyMeasurement: true, minTcb: { snp: 29 } });
check('a floor the report does not meet: refused', /below the floor/.test(r.error || ''), JSON.stringify(r));

r = await tryOpen({ allowAnyMeasurement: true, minTcb: { bl: 12, tee: 0, snp: 28, ucode: 88 } });
check('a floor the report meets: reaches attested', !!r.status, JSON.stringify(r));

r = await tryOpen({ allowedMeasurements: ['ff'.repeat(48)], allowAnyMeasurement: true });
check('a list that does not match is refused even with the waiver', /not an allowed fingerprint/.test(r.error || ''), JSON.stringify(r));

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
