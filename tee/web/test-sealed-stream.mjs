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

function tcpPipe(port, { tamper = false } = {}) {
  const sock = net.connect(port, '127.0.0.1');
  let n = 0;
  const pipe = { onbytes: null, onclose: null, send: (b) => sock.write(b), close: () => sock.destroy(),
    ready: new Promise((res, rej) => { sock.on('connect', res); sock.on('error', rej); }) };
  sock.on('data', (d) => { const u8 = new Uint8Array(d); if (tamper && ++n === 3) u8[u8.length - 1] ^= 0x01; pipe.onbytes?.(u8); });
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
  const pipe = tcpPipe(18444, { tamper: true }); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
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

box.kill();
console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
