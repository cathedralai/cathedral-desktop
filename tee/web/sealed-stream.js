// Sealed stream client: Noise_NK_25519_AESGCM_SHA256 initiator over any byte pipe, with the box's
// static key proven by its SEV-SNP report (tee/SEALED-STREAM.md). WebCrypto only; runs in browsers
// (Chrome 133+, Safari 17+, Firefox 130+ for X25519) and in Node 20+.
//
//   const s = await SealedStream.open({ pipe, target: 'vnc', ticket, verify: { certs, allowedMeasurements } });
//   s.onmessage = (bytes) => ...; s.send(bytes); s.close();
//
// `pipe` is a byte pipe: { send(Uint8Array), onbytes: set by the client, close() }. Frames are
// reassembled here, so WebSocket relays (websockify) may split or merge TCP chunks freely.
// `SealedStream.websocketLike(stream)` returns a WebSocket-shaped object that noVNC's RFB accepts.

import { verifySnp, parseReport, kdsVcekUrl, sha256, equal, hex } from './snp-verify.js';

const subtle = globalThis.crypto.subtle;
const PROTOCOL = 'Noise_NK_25519_AESGCM_SHA256';
const PROLOGUE = 'sealed-stream/v1';
const MAX_FRAME = 1 << 20;
const MAX_DATA = 64 << 10;
const REKEY_EVERY = 1 << 20;
const te = new TextEncoder();
const td = new TextDecoder();

const b64u = {
  enc: (u8) => btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), (c) => c.charCodeAt(0)),
};
const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

async function hmac(key, data) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', k, data));
}
async function hkdf2(ck, ikm) {
  const temp = await hmac(ck, ikm);
  const out1 = await hmac(temp, new Uint8Array([1]));
  const out2 = await hmac(temp, cat(out1, new Uint8Array([2])));
  return [out1, out2];
}

class CipherState {
  constructor() { this.key = null; this.n = 0n; this.frames = 0; }
  async init(k) { this.raw = k; this.key = await subtle.importKey('raw', k, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); this.n = 0n; }
  nonce(n) { const iv = new Uint8Array(12); new DataView(iv.buffer).setBigUint64(4, n); return iv; }
  async encryptWithAd(ad, pt) {
    if (!this.key) return pt;
    if (this.n === 0xffffffffffffffffn) throw new Error('nonce exhausted');
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: this.nonce(this.n), additionalData: ad }, this.key, pt));
    this.n++;
    return ct;
  }
  async decryptWithAd(ad, ct) {
    if (!this.key) return ct;
    if (this.n === 0xffffffffffffffffn) throw new Error('nonce exhausted');
    let pt;
    try { pt = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: this.nonce(this.n), additionalData: ad }, this.key, ct)); }
    catch { throw new Error('authentication failed'); }
    this.n++;
    return pt;
  }
  async rekey() {
    const nk = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: this.nonce(0xffffffffffffffffn) }, this.key, new Uint8Array(32))).slice(0, 32);
    await this.init(nk);
  }
  async encrypt(pt) {
    if (pt.length > MAX_DATA) throw new Error('frame over maxData');
    const ct = await this.encryptWithAd(new Uint8Array(0), pt);
    if (++this.frames % REKEY_EVERY === 0) await this.rekey();
    return ct;
  }
  async decrypt(ct) {
    const pt = await this.decryptWithAd(new Uint8Array(0), ct);
    if (++this.frames % REKEY_EVERY === 0) await this.rekey();
    return pt;
  }
}

class Handshake {
  static async create(prologue, rs) {
    const hs = new Handshake();
    const name = te.encode(PROTOCOL);
    hs.h = name.length <= 32 ? cat(name, new Uint8Array(32 - name.length)) : await sha256(name);
    hs.ck = hs.h.slice();
    hs.cs = new CipherState();
    hs.rs = await subtle.importKey('raw', rs, { name: 'X25519' }, false, []);
    await hs.mixHash(prologue);
    await hs.mixHash(rs);
    return hs;
  }
  async mixHash(data) { this.h = await sha256(cat(this.h, data)); }
  async mixKey(ikm) { const [ck, k] = await hkdf2(this.ck, ikm); this.ck = ck; await this.cs.init(k); }
  async dh(priv, pub) { return new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256)); }
  async writeMessage1(payload) {
    this.e = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const eb = new Uint8Array(await subtle.exportKey('raw', this.e.publicKey));
    await this.mixHash(eb);
    await this.mixKey(await this.dh(this.e.privateKey, this.rs));
    const ct = await this.cs.encryptWithAd(this.h, payload);
    await this.mixHash(ct);
    return cat(eb, ct);
  }
  async readMessage2(msg) {
    if (msg.length < 32) throw new Error('short message 2');
    const re = await subtle.importKey('raw', msg.slice(0, 32), { name: 'X25519' }, false, []);
    await this.mixHash(msg.slice(0, 32));
    await this.mixKey(await this.dh(this.e.privateKey, re));
    const pt = await this.cs.decryptWithAd(this.h, msg.slice(32));
    await this.mixHash(msg.slice(32));
    return pt;
  }
  async split() {
    const [k1, k2] = await hkdf2(this.ck, new Uint8Array(0));
    const send = new CipherState(); await send.init(k1);
    const recv = new CipherState(); await recv.init(k2);
    return { send, recv };
  }
}

/** Length-prefixed frame reader over an arbitrary byte stream. */
class Frames {
  constructor() { this.buf = new Uint8Array(0); this.waiters = []; this.queue = []; this.closed = false; }
  push(bytes) {
    this.buf = cat(this.buf, bytes);
    for (;;) {
      if (this.buf.length < 4) break;
      const n = new DataView(this.buf.buffer, this.buf.byteOffset).getUint32(0);
      if (n > MAX_FRAME) { this.fail(new Error('frame too large')); return; }
      if (this.buf.length < 4 + n) break;
      const frame = this.buf.slice(4, 4 + n);
      this.buf = this.buf.slice(4 + n);
      const w = this.waiters.shift();
      if (w) w.resolve(frame); else this.queue.push(frame);
    }
  }
  fail(err) { this.closed = true; this.err = err; for (const w of this.waiters.splice(0)) w.reject(err); }
  next() {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.closed) return Promise.reject(this.err || new Error('closed'));
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}
const frame = (b) => { const h = new Uint8Array(4); new DataView(h.buffer).setUint32(0, b.length); return cat(h, b); };

export class SealedStream {
  /**
   * verify: { certs: {ark, ask, vcek?}, allowedMeasurements: [], allowAnyMeasurement?: false, product, fetchVcek?: async (url) => Uint8Array, allowDev?: false }
   * The box's static key must be bound as sha256(static) in REPORT_DATA[32:64]; REPORT_DATA[0:32] is the
   * TLS SPKI hash from AB#361 (checked only if verify.tlsSpki is given).
   */
  static async open({ pipe, target, ticket = '', verify, onstatus = () => {} }) {
    const frames = new Frames();
    pipe.onbytes = (b) => frames.push(b);
    pipe.onclose = () => frames.fail(new Error('pipe closed'));
    const s = new SealedStream(pipe, frames);
    onstatus('hello');
    pipe.send(frame(te.encode(JSON.stringify({ v: 1 }))));
    const att = JSON.parse(td.decode(await frames.next()));
    if (att.error) throw new Error(`box: ${att.error}`);
    const rs = b64u.dec(att.static);
    const report = att.report ? b64u.dec(att.report) : null;
    if (!report) {
      if (!verify?.allowDev) throw new Error('box presented no attestation report');
      s.attestation = { ok: false, dev: true };
      onstatus('dev box, no attestation');
    } else {
      onstatus('verifying report');
      const rep = parseReport(report);
      const certs = { ...(verify.certs || {}) };
      for (const k of ['vcek', 'ask', 'ark']) if (!certs[k] && att.certs?.[k]) certs[k] = b64u.dec(att.certs[k]);
      if (!certs.vcek && verify.fetchVcek) certs.vcek = await verify.fetchVcek(kdsVcekUrl(rep, verify.product));
      // REPORT_DATA = sha256(canonical(binding)) || zeros; the binding names the stream key and the TLS key.
      if (typeof att.binding !== 'string') throw new Error('box presented no key binding');
      const bindingBytes = te.encode(att.binding);
      let bound;
      try { bound = JSON.parse(att.binding); } catch { throw new Error('binding is not JSON'); }
      const named = bound?.sealed_stream;
      if (named?.schema !== 'sealed-stream/v1' || typeof named.x25519_public_b64 !== 'string') throw new Error('binding has no sealed_stream key');
      if (!equal(Uint8Array.from(atob(named.x25519_public_b64), (c) => c.charCodeAt(0)), rs)) throw new Error('binding names a different stream key than the box presented');
      if (verify.tlsSpki && bound.tls_spki_sha256 !== hex(await sha256(verify.tlsSpki))) throw new Error('binding names a different TLS key');
      const binding = { first: await sha256(bindingBytes), second: null };
      s.attestation = await verifySnp({ report, certs, product: verify.product, binding, allowedMeasurements: verify.allowedMeasurements || [], allowAnyMeasurement: verify.allowAnyMeasurement === true });
      s.attestation.binding = bound;
      onstatus(`attested ${s.attestation.measurement.slice(0, 12)}${s.attestation.testMode ? ' (any build accepted)' : ''}`);
    }
    const prologue = cat(te.encode(PROLOGUE), await sha256(report || new Uint8Array(0)));
    const hs = await Handshake.create(prologue, rs);
    pipe.send(frame(await hs.writeMessage1(te.encode(JSON.stringify({ target, ticket })))));
    const ready = JSON.parse(td.decode(await hs.readMessage2(await frames.next())));
    if (!ready.ok) throw new Error(`box refused: ${ready.error}`);
    const { send, recv } = await hs.split();
    s.send_ = send; s.recv_ = recv; s.target = target;
    onstatus(`open ${target}`);
    s.loop();
    return s;
  }
  constructor(pipe, frames) { this.pipe = pipe; this.frames = frames; this.onmessage = null; this.onclose = null; this.closed = false; this.sending = Promise.resolve(); this.pending = null; }
  async loop() {
    try {
      for (;;) {
        const ct = await this.frames.next();
        const pt = await this.recv_.decrypt(ct);
        // Plaintext can arrive before anyone is listening: the stream is open as
        // soon as the handshake ends, and the VNC server's banner lands while
        // rfb.js is still being imported. Dropping it loses the session.
        if (this.onmessage) this.onmessage(pt);
        else (this.pending ||= []).push(pt);
      }
    } catch (e) { this.close(e); }
  }
  send(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let o = 0; o < u8.length; o += MAX_DATA) {
      const chunk = u8.slice(o, o + MAX_DATA);
      this.sending = this.sending.then(async () => this.pipe.send(frame(await this.send_.encrypt(chunk)))).catch((e) => this.close(e));
    }
  }
  close(err) { if (this.closed) return; this.closed = true; try { this.pipe.close(); } catch {} this.onclose?.(err); }

  /** A WebSocket-shaped object for noVNC: `new RFB(el, SealedStream.websocketLike(stream))`. */
  static websocketLike(stream) {
    const ws = { binaryType: 'arraybuffer', protocol: 'binary', readyState: 1, bufferedAmount: 0,
      onopen: null, onclose: null, onerror: null,
      send: (d) => stream.send(d instanceof ArrayBuffer ? new Uint8Array(d) : d),
      close: () => stream.close(),
      addEventListener(t, f) { ws['on' + t] = f; }, removeEventListener() {} };
    // noVNC's Websock.attach assigns ws.onmessage directly, so the handover of
    // frames buffered before it attached hangs off that assignment, not off a
    // timer: whenever the handler lands, the backlog goes out right after it.
    // Deferred to a microtask so the bytes arrive after attach has returned and
    // RFB has run its open step, never from inside it.
    let handler = null;
    const flush = () => { for (const pt of (stream.pending || []).splice(0)) stream.onmessage(pt); };
    Object.defineProperty(ws, 'onmessage', { enumerable: true, configurable: true,
      get: () => handler, set: (f) => { handler = f; if (f) queueMicrotask(flush); } });
    stream.onmessage = (pt) => handler?.({ data: pt.buffer.slice(pt.byteOffset, pt.byteOffset + pt.byteLength) });
    stream.onclose = (err) => { ws.readyState = 3; if (err) ws.onerror?.({ message: err.message }); ws.onclose?.({ code: err ? 1006 : 1000, reason: err?.message || '', wasClean: !err }); };
    // No onopen here. readyState is 1 already, so RFB calls its open step itself
    // when it attaches (core/rfb.js, "if (this._sock.readyState === 'open')"); a
    // second open runs the handshake twice and fails the session.
    return ws;
  }
}

/** A byte pipe over a browser WebSocket (websockify relay). */
export function websocketPipe(url) {
  const ws = new WebSocket(url, ['binary']);
  ws.binaryType = 'arraybuffer';
  const pipe = { onbytes: null, onclose: null, ready: new Promise((res, rej) => { ws.onopen = res; ws.onerror = () => rej(new Error('websocket error')); }),
    send: (b) => ws.send(b), close: () => ws.close() };
  ws.onmessage = (ev) => pipe.onbytes?.(new Uint8Array(ev.data));
  ws.onclose = () => pipe.onclose?.();
  return pipe;
}

export { b64u, hex, equal };
