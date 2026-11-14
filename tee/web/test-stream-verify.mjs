// node tee/web/test-stream-verify.mjs
// SealedStream.open hands the caller's verification options on to the report verifier. A fake box sends the
// saved chip report as its first frame; each case checks whether the open is refused or gets as far as
// "attested", which is where the real handshake would begin. No network and no boxd.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as ss from './sealed-stream.js';
const { SealedStream } = ss;

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

// ---- customer mode (AB#353 WP2)
const vec = JSON.parse(readFileSync(join(fx, '..', 'testdata', 'customer_host_data_v1.json'), 'utf8'));
// A customer key pair made here: the client checks that the ticket is signed by the customer key before it sends anything.
const kp = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const kpOther = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
const b64uOf = (u8) => Buffer.from(u8).toString('base64url');
const customerKey = b64uOf(new Uint8Array(await globalThis.crypto.subtle.exportKey('raw', kp.publicKey)));
const ticketBy = async (pair) => { const bb = new TextEncoder().encode('{"box":"x","target":"job"}'); return `${b64uOf(bb)}.${b64uOf(new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', pair.privateKey, bb)))}`; };
const goodTicket = await ticketBy(kp);

// Like tryOpen, but counts what the client wrote and keeps the plaintext of message 1 (the Handshake is patched only to read it).
// noReport: a box that presents no attestation report at all, which is what allowDev exists to accept.
async function probe(verify, { noReport = false, ticket } = {}) {
  ticket ??= verify.customerKey === undefined ? '' : goodTicket;
  const sent = []; const payloads = [];
  const orig = ss.Handshake?.prototype.writeMessage1;
  if (orig) ss.Handshake.prototype.writeMessage1 = function (p) { payloads.push(new TextDecoder().decode(p)); return orig.call(this, p); };
  const att = noReport ? { static: enc(staticKey) } : { static: enc(staticKey), report: enc(report), binding: bindingText };
  const pipe = { onbytes: null, onclose: null, close() { this.onclose?.(); }, ready: Promise.resolve(),
    send(b) { sent.push(b); if (sent.length === 1) queueMicrotask(() => this.onbytes?.(frame(att))); } };
  let status = null, error = null;
  try {
    await SealedStream.open({ pipe, target: 'job', ticket, verify: { certs, ...verify }, onstatus: (m) => { if (m.startsWith('attested') || m.startsWith('dev box')) { status = m; pipe.close(); } } });
  } catch (e) { error = e.message; } finally { if (orig) ss.Handshake.prototype.writeMessage1 = orig; }
  return { sent: sent.length, payloads, status, error };
}
const listed = { allowedMeasurements: [measurement] };

let p = await probe({ ...listed, customerKey });
check('customer key set, fixture HOST_DATA zero: refused with a named reason', /HOST_DATA.*zero/i.test(p.error || ''), JSON.stringify(p.error));
check('a refused check sends nothing after HELLO and does not retry', p.sent === 1 && p.payloads.length === 0, `writes ${p.sent}, message 1 count ${p.payloads.length}`);
// Reconnect after a reboot is a new open with a new report: the check runs again every time, nothing is cached from the first.
const verifyOpts = { ...listed, customerKey };
const again = [await probe(verifyOpts), await probe(verifyOpts)];
check('a second open (reconnect) runs the customer check again', again.every((x) => /HOST_DATA/.test(x.error || '') && x.sent === 1), JSON.stringify(again.map((x) => x.error)));

// Every waiver is refused in customer mode. allowDev skips verifySnp entirely today, so it is tested against a box with no report.
p = await probe({ ...listed, allowDev: true, customerKey }, { noReport: true });
check('customer key + allowDev, box with no report: refused by name, nothing sent after HELLO', /customer mode.*allowDev/i.test(p.error || '') && !p.status && p.payloads.length === 0, JSON.stringify(p));
p = await probe({ ...listed, allowDev: true, customerKey });
check('customer key + allowDev, box with a report: refused by name', /customer mode.*allowDev/i.test(p.error || '') && p.payloads.length === 0, JSON.stringify(p.error));
p = await probe({ allowAnyMeasurement: true, customerKey });
check('customer key + allowAnyMeasurement (what nofp=1 becomes on the page): refused by name', /customer mode.*allowAnyMeasurement/i.test(p.error || '') && p.payloads.length === 0, JSON.stringify(p.error));
p = await probe({ allowedMeasurements: [], customerKey });
check('customer key + empty fingerprint list: refused by name', /customer mode.*fingerprint list/i.test(p.error || '') && p.payloads.length === 0, JSON.stringify(p.error));

p = await probe({ allowAnyMeasurement: true });
check('no customer key: reaches attested as on main', !!p.status, JSON.stringify(p));
check('no customer key: message 1 is exactly {"target","ticket"}, no customer field', p.payloads.length === 1 && p.payloads[0] === '{"target":"job","ticket":""}', JSON.stringify(p.payloads));
p = await probe({ allowDev: true }, { noReport: true });
check('no customer key: allowDev still accepts a dev box, as on main', /dev box/.test(p.status || ''), JSON.stringify(p));

try {
  check('message 1 payload with a key adds only the customer field', ss.message1Payload('job', 'T', customerKey) === `{"target":"job","ticket":"T","customer":"${customerKey}"}`);
  check('message 1 payload without a key is byte for byte the old one', ss.message1Payload('job', 'T') === JSON.stringify({ target: 'job', ticket: 'T' }));
} catch (e) { check('message 1 payload', false, e.message); }

for (const [label, bad] of [['empty string', ''], ['not base64url', '!'.repeat(43)], ['31 bytes', Buffer.alloc(31).toString('base64url')], ['33 bytes', Buffer.alloc(33).toString('base64url')]]) {
  p = await probe({ ...listed, customerKey: bad });
  check(`customer key ${label}: usage error before anything is written`, /^invalid customer key/.test(p.error || '') && p.sent === 0, `${p.error} writes ${p.sent}`);
}

// ---- review fixes (AB#353)
p = await probe({ ...listed, customerKey }, { ticket: '' });
check('customer key + empty ticket: refused by name before anything is written', /customer mode needs a ticket/.test(p.error || '') && p.sent === 0, JSON.stringify(p));
p = await probe({ ...listed, customerKey }, { ticket: await ticketBy(kpOther) });
check('customer key + ticket signed by another key: usage error before anything is written', /signed by the customer key/.test(p.error || '') && p.sent === 0, JSON.stringify(p));

// The box has to say, inside its authenticated answer, that it is in customer mode. checkReady is that decision.
try {
  ss.checkReady({ ok: true, mode: 'customer' }, customerKey);
  check('message 2 with mode customer and a customer key: accepted', true);
} catch (e) { check('message 2 with mode customer and a customer key: accepted', false, e.message); }
for (const [label, ready] of [['no marker', { ok: true }], ['another mode', { ok: true, mode: 'cathedral' }], ['a non-string mode', { ok: true, mode: ['customer'] }]]) {
  try { ss.checkReady(ready, customerKey); check(`customer key, message 2 with ${label}: refused`, false, 'accepted'); }
  catch (e) { check(`customer key, message 2 with ${label}: refused with a named reason`, /did not confirm customer mode/.test(e.message), e.message); }
}
try {
  ss.checkReady({ ok: true }, undefined); ss.checkReady({ ok: true, mode: 'customer' }, undefined);
  check('no customer key: message 2 is accepted with or without the member', true);
} catch (e) { check('no customer key: message 2 is accepted with or without the member', false, e.message); }

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
