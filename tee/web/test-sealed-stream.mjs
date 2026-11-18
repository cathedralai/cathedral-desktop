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

// A TCP data event is not a frame: boxd writes a frame as two writes (4-byte length, then body), so the events
// can split anywhere. `mutate(index, frame)` therefore works on whole frames: the box's bytes are reassembled
// into length-prefixed frames (index 0 is ATTEST, 1 is message 2, 2 is the first frame after the handshake),
// each frame goes through `mutate` (return the bytes to pass on) and is delivered as one chunk.
function tcpPipe(port, { mutate = null } = {}) {
  const sock = net.connect(port, '127.0.0.1');
  const pipe = { onbytes: null, onclose: null, send: (b) => sock.write(b), close: () => sock.destroy(),
    ready: new Promise((res, rej) => { sock.on('connect', res); sock.on('error', rej); }) };
  let buf = new Uint8Array(0), index = 0;
  sock.on('data', (d) => {
    const u8 = new Uint8Array(d);
    if (!mutate) { pipe.onbytes?.(u8); return; }
    const all = new Uint8Array(buf.length + u8.length); all.set(buf); all.set(u8, buf.length); buf = all;
    while (buf.length >= 4) {
      const total = 4 + new DataView(buf.buffer, buf.byteOffset).getUint32(0);
      if (buf.length < total) break;
      const out = mutate(index++, buf.slice(0, total));
      buf = buf.slice(total);
      if (out.length) pipe.onbytes?.(out);
    }
  });
  sock.on('close', () => pipe.onclose?.());
  return pipe;
}
// Change the first frame after the handshake and pass everything else on untouched.
const onFirstData = (change) => (i, frame) => (i === 2 ? change(frame) : frame);
const flipBodyByte = onFirstData((f) => { const g = f.slice(); g[g.length - 1] ^= 0x01; return g; });
const setLength = (delta) => onFirstData((f) => {
  const g = f.slice(); const n = new DataView(g.buffer).getUint32(0) + delta;
  new DataView(g.buffer).setUint32(0, n); return g;
});
// Open a stream through `mutate`, send one job, and report how the stream ended within `ms`.
async function endOf(mutate, ms) {
  const pipe = tcpPipe(18444, { mutate }); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  const got = [];
  s.onmessage = (pt) => got.push(td.decode(pt));
  const closed = new Promise((res) => { s.onclose = (err) => res(err); });
  s.send(te.encode('JOB 9\n'));
  const err = await Promise.race([closed, new Promise((r) => setTimeout(() => r(null), ms))]);
  s.close(); pipe.close();
  return { err, got };
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

// A flipped bit inside the body of the first frame after the handshake. The frame reaches the client whole, so
// the only way out is the AEAD check: no "pipe closed" alternative is needed, and one would hide a hang.
try {
  const { err, got } = await endOf(flipBodyByte, 2000);
  check('tampered frame closes the stream', /authentication failed/.test(err?.message || ''), err?.message || 'no close');
  check('a tampered frame delivers nothing', got.length === 0, JSON.stringify(got));
} catch (e) { check('tamper case', false, e.message); }

// The length prefix of the first frame after the handshake, one byte shorter and one byte longer.
try {
  const { err, got } = await endOf(setLength(-1), 2000);
  check('a length one byte too short closes the stream as a failed authentication', /authentication failed/.test(err?.message || ''), err?.message || 'no close');
  check('a length one byte too short delivers nothing', got.length === 0, JSON.stringify(got));
} catch (e) { check('short length case', false, e.message); }
try {
  // TODAY'S BEHAVIOUR, not a requirement: the client reads a frame by its length, so a length one byte too long
  // makes it wait for a byte the box never sends. Nothing closes and nothing is delivered. (An attacker who can
  // do this can also drop the packets, which gives the same hang; the frame is never accepted.) If the client
  // later adds a read timeout, change this case to expect a close.
  const { err, got } = await endOf(setLength(+1), 1500);
  check('a length one byte too long leaves the client waiting (today: no close, nothing delivered)', err === null && got.length === 0, err?.message || JSON.stringify(got));
} catch (e) { check('long length case', false, e.message); }

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

box.kill();
console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
