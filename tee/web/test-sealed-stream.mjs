// node tee/web/test-sealed-stream.mjs [path/to/boxd]
// Interop: starts `boxd -dev -noticket` (no TSM, loopback), opens a sealed stream to target "job",
// sends JOB lines inside the stream, checks the answers, then checks that a bit flip on the wire
// closes the stream with an authentication failure.
import { spawn } from 'node:child_process';
import net from 'node:net';
import { SealedStream } from './sealed-stream.js';

const boxd = process.argv[2] || './boxd';
const te = new TextEncoder(), td = new TextDecoder();
let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!ok) failures++; };

const box = spawn(boxd, ['-dev', '-noticket', '-tls', '127.0.0.1:18443', '-stream', '127.0.0.1:18444'], { stdio: ['ignore', 'ignore', 'pipe'] });
await new Promise((res, rej) => { box.stderr.on('data', (d) => { if (/LISTEN/.test(d.toString())) res(); }); box.on('exit', (c) => rej(new Error(`boxd exited ${c}`))); setTimeout(() => rej(new Error('boxd did not listen')), 5000); });

// pipe.tamperNext = true flips one bit in the ciphertext of the next frame read from the socket.
// Armed after the handshake, at a frame boundary, and aimed past the 4-byte length header: boxd
// writes header and body separately, so TCP chunks do not line up with frames, and flipping the
// last byte of the third chunk sometimes hit the header instead (CI: "no close" within 2s).
function tcpPipe(port) {
  const sock = net.connect(port, '127.0.0.1');
  const pipe = { onbytes: null, onclose: null, tamperNext: false, send: (b) => sock.write(b), close: () => sock.destroy(),
    ready: new Promise((res, rej) => { sock.on('connect', res); sock.on('error', rej); }) };
  let skip = 4; // bytes of the next frame's length header still to pass before the first ciphertext byte
  sock.on('data', (d) => {
    const u8 = new Uint8Array(d);
    if (pipe.tamperNext) {
      if (skip < u8.length) { u8[skip] ^= 0x01; pipe.tamperNext = false; skip = 4; } else skip -= u8.length;
    }
    pipe.onbytes?.(u8);
  });
  sock.on('close', () => pipe.onclose?.());
  return pipe;
}

try {
  const pipe = tcpPipe(18444); await pipe.ready;
  const statuses = [];
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true }, onstatus: (m) => statuses.push(m) });
  check('handshake with a dev box (no report)', s.attestation?.dev === true, statuses.join(' > '));
  const replies = [];
  s.onmessage = (pt) => replies.push(td.decode(pt));
  for (let i = 1; i <= 3; i++) s.send(te.encode(`JOB ${i}\n`));
  await new Promise((r) => setTimeout(r, 300));
  check('three JOB round trips inside the stream', replies.join('') === 'DONE 1 42\nDONE 2 42\nDONE 3 42\n', JSON.stringify(replies));
  s.close();
} catch (e) { check('dev stream', false, e.message); }

try {
  const pipe = tcpPipe(18444); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  pipe.tamperNext = true;
  const closed = new Promise((res) => { s.onclose = (err) => res(err); });
  s.send(te.encode('JOB 9\n'));
  const err = await Promise.race([closed, new Promise((r) => setTimeout(() => r(new Error('no close')), 2000))]);
  check('tampered frame closes the stream', /authentication failed|pipe closed/.test(err?.message || ''), err?.message);
} catch (e) { check('tamper case', /authentication failed/.test(e.message), e.message); }

try {
  const pipe = tcpPipe(18444); await pipe.ready;
  await SealedStream.open({ pipe, target: 'job', verify: {} });
  check('dev box refused when attestation is required', false);
} catch (e) { check('dev box refused when attestation is required', /no attestation/.test(e.message), e.message); }

// The noVNC adapter, which is where the desktop was lost on c48 run 3: the box's
// first bytes (the RFB banner) land while rfb.js is still being imported, and
// noVNC runs its own open step at attach because readyState is already 1.
try {
  const pipe = tcpPipe(18444); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  s.send(te.encode('JOB 5\n'));
  await new Promise((r) => setTimeout(r, 300));            // reply arrives with nobody listening
  check('frames with no listener are kept, not dropped', (s.pending || []).length === 1, `pending ${(s.pending || []).length}`);

  const ws = SealedStream.websocketLike(s);
  let opens = 0;
  ws.onopen = () => { opens++; };                           // noVNC assigns these directly
  const seen = [];
  ws.onmessage = (e) => seen.push(td.decode(new Uint8Array(e.data)));
  await new Promise((r) => setTimeout(r, 50));
  check('the backlog reaches the listener that attached late', seen.join('') === 'DONE 5 42\n', JSON.stringify(seen));
  check('no onopen of our own (noVNC fires its own at attach)', opens === 0, `${opens} opens`);
  check('readyState is open, which is what makes it do that', ws.readyState === 1);

  s.send(te.encode('JOB 6\n'));
  await new Promise((r) => setTimeout(r, 300));
  check('and later frames go straight through', seen.join('') === 'DONE 5 42\nDONE 6 42\n', JSON.stringify(seen));
  s.close();
} catch (e) { check('noVNC adapter', false, e.message); }

// boxd -dev -customer: the browser client must keep refusing a dev box in customer mode, and refuse the waiver that would let it in.
{
  const cbox = spawn(boxd, ['-dev', '-customer', '-dev-host-data', 'ab'.repeat(32), '-tls', '127.0.0.1:18543', '-stream', '127.0.0.1:18544'], { stdio: ['ignore', 'ignore', 'pipe'] });
  try {
    await new Promise((res, rej) => { cbox.stderr.on('data', (d) => { if (/LISTEN/.test(d.toString())) res(); }); cbox.on('exit', (c) => rej(new Error(`boxd exited ${c}`))); setTimeout(() => rej(new Error('boxd did not listen')), 5000); });
    // A real key pair: the client checks that the ticket is signed by the customer key before it sends anything.
    const kp = await globalThis.crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const key = Buffer.from(await globalThis.crypto.subtle.exportKey('raw', kp.publicKey)).toString('base64url');
    const bb = te.encode('{"box":"x","target":"job"}');
    const ticket = `${Buffer.from(bb).toString('base64url')}.${Buffer.from(await globalThis.crypto.subtle.sign('Ed25519', kp.privateKey, bb)).toString('base64url')}`;
    for (const [label, verify, re] of [
      ['a dev box', { customerKey: key, allowedMeasurements: ['ab'.repeat(48)] }, /no attestation/],
      ['allowDev', { customerKey: key, allowedMeasurements: ['ab'.repeat(48)], allowDev: true }, /customer mode.*allowDev/],
      ['allowAnyMeasurement', { customerKey: key, allowAnyMeasurement: true }, /customer mode.*allowAnyMeasurement/]]) {
      const pipe = tcpPipe(18544); await pipe.ready;
      try { await SealedStream.open({ pipe, target: 'job', ticket, verify }); check(`customer mode: browser client refuses ${label}`, false, 'opened'); }
      catch (e) { check(`customer mode: browser client refuses ${label}`, re.test(e.message), e.message); }
      pipe.close();
    }
  } catch (e) { check('customer mode box', false, e.message); }
  cbox.kill();
}

box.kill();
console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
