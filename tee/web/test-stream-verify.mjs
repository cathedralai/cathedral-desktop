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

// ---- review round 2 (AB#353): the marker check and the HOST_DATA call site, run through the real code with the report check replaced
// inside this test only. Each case loads a temp copy of the product file with ONE import or call swapped for a test double; the
// rest of the file is the product code as it is, so deleting checkReady(...) or re-inlining a slice in the product file fails here.
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
const web = dirname(fileURLToPath(import.meta.url));
const tmp = mkdtempSync(join(tmpdir(), 'wp2-'));
const realSnp = pathToFileURL(join(web, 'snp-verify.js')).href;
const swap = (src, from, to) => { if (!src.includes(from)) throw new Error(`test double target not found: ${from}`); return src.replace(from, to); };

// (1) sealed-stream.js with verifySnp replaced by a double that returns a fixed attestation object.
writeFileSync(join(tmp, 'snp-stub.mjs'), `export * from '${realSnp}'; export async function verifySnp() { return globalThis.__attestation; }`);
writeFileSync(join(tmp, 'sealed-stream.mjs'), swap(readFileSync(join(web, 'sealed-stream.js'), 'utf8'), "from './snp-verify.js'", "from './snp-stub.mjs'"));
const SS = await import(pathToFileURL(join(tmp, 'sealed-stream.mjs')).href);

const subtle = globalThis.crypto.subtle;
const cat = (...p) => { const o = new Uint8Array(p.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of p) { o.set(x, i); i += x.length; } return o; };
const sha = async (b) => new Uint8Array(await subtle.digest('SHA-256', b));
const hmacS = async (k, d) => new Uint8Array(await subtle.sign('HMAC', await subtle.importKey('raw', k, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']), d));
const hk2 = async (ck, ikm) => { const t = await hmacS(ck, ikm); const o1 = await hmacS(t, new Uint8Array([1])); return [o1, await hmacS(t, cat(o1, new Uint8Array([2])))]; };
const dh = async (priv, pubRaw) => new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: await subtle.importKey('raw', pubRaw, { name: 'X25519' }, false, []) }, priv, 256));

// The box side: HELLO -> ATTEST, message 1 -> message 2 (given plaintext), then record anything else the client writes.
async function playBox(ready) {
  const stat = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const spub = new Uint8Array(await subtle.exportKey('raw', stat.publicKey));
  const att = { v: 1, static: enc(spub), report: enc(report), binding: JSON.stringify({ sealed_stream: { schema: 'sealed-stream/v1', x25519_public_b64: btoa(String.fromCharCode(...spub)) } }) };
  const shared = { ok: true, measurement: 'ab'.repeat(48), testMode: false };
  globalThis.__attestation = shared;
  const extra = []; let n = 0; let chain = Promise.resolve();
  const pipe = { onbytes: null, onclose: null, closed: false, close() { this.closed = true; this.onclose?.(); }, ready: Promise.resolve(),
    send(b) { chain = chain.then(async () => {
      n++;
      if (n === 1) { pipe.onbytes?.(frame(att)); return; }
      if (n > 2) { extra.push(b); return; }
      const msg1 = b.slice(4);
      const name = new TextEncoder().encode('Noise_NK_25519_AESGCM_SHA256');
      let h = cat(name, new Uint8Array(32 - name.length)); let ck = h;
      const mix = async (d) => { h = await sha(cat(h, d)); };
      await mix(cat(new TextEncoder().encode('sealed-stream/v1'), await sha(report))); await mix(spub);
      const re = msg1.slice(0, 32); await mix(re);
      [ck] = await hk2(ck, await dh(stat.privateKey, re)); await mix(msg1.slice(32));
      const e = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
      const epub = new Uint8Array(await subtle.exportKey('raw', e.publicKey)); await mix(epub);
      let k; [ck, k] = await hk2(ck, await dh(e.privateKey, re));
      const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(12), additionalData: h }, await subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['encrypt']), new TextEncoder().encode(ready)));
      { const body = cat(epub, ct); const out = new Uint8Array(4 + body.length); new DataView(out.buffer).setUint32(0, body.length); out.set(body, 4); pipe.onbytes?.(out); }
    }); } };
  return { pipe, extra, shared, settle: () => chain };
}
async function openWithMarker(ready) {
  const box = await playBox(ready);
  let result;
  try { result = await SS.SealedStream.open({ pipe: box.pipe, target: 'job', ticket: goodTicket, verify: { certs, allowedMeasurements: [measurement], customerKey } }); }
  catch (e) { result = e; }
  await new Promise((r) => setTimeout(r, 50)); await box.settle();
  return { result, ...box };
}
let m = await openWithMarker('{"ok":true,"mode":"customer"}');
check('marker flow: message 2 with the marker gives a stream marked bound', !(m.result instanceof Error) && m.result.attestation?.customerBound === true, String(m.result?.message));
m.result.close?.();
m = await openWithMarker('{"ok":true}');
check('marker flow: message 2 without the marker is refused with the named reason', m.result instanceof Error && /did not confirm customer mode/.test(m.result.message), String(m.result?.message));
check('marker flow: nothing more is sent after the refusal', m.extra.length === 0, `${m.extra.length} frames`);
check('marker flow: the pipe is closed at once', m.pipe.closed === true);
check('marker flow: the bound flag is never set', m.shared.customerBound === undefined, JSON.stringify(m.shared));

// (2) snp-verify.js with the report signature check replaced, so a report with a customer's HOST_DATA (never signed by a chip)
// can reach the HOST_DATA comparison through verifySnp itself.
writeFileSync(join(tmp, 'snp-nosig.mjs'), swap(readFileSync(join(web, 'snp-verify.js'), 'utf8'), 'await verifyReportSignature(rep, chain.vcekSpki)', 'true'));
const NS = await import(pathToFileURL(join(tmp, 'snp-nosig.mjs')).href);
const hdAt = (at, hexv) => { const b = report.slice(); b.set(Uint8Array.from(hexv.match(/../g), (x) => parseInt(x, 16)), at); return b; };
const rb = { first: await sha(new TextEncoder().encode(bindingText)), second: null };
const vopts = { certs, binding: rb, allowedMeasurements: [measurement], customerKey: vec.customer.public_key_b64u };
try {
  const r = await NS.verifySnp({ report: hdAt(0xC0, vec.customer.host_data_hex), ...vopts });
  check('HOST_DATA pin: the right value at 0xC0 passes the whole check path', r.ok === true);
} catch (e) { check('HOST_DATA pin: the right value at 0xC0 passes the whole check path', false, e.message); }
try { await NS.verifySnp({ report: hdAt(0xE0, vec.customer.host_data_hex), ...vopts }); check('HOST_DATA pin: the right value at 0xE0 instead is refused as zero', false, 'accepted'); }
catch (e) { check('HOST_DATA pin: the right value at 0xE0 instead is refused as zero', /HOST_DATA is zero/.test(e.message), e.message); }
try { await NS.verifySnp({ report: hdAt(0xC0, vec.other_customer.host_data_hex), ...vopts }); check('HOST_DATA pin: another key\'s value at 0xC0 is refused', false, 'accepted'); }
catch (e) { check('HOST_DATA pin: another key\'s value at 0xC0 is refused', /does not match/.test(e.message), e.message); }

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
