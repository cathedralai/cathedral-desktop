// node tee/web/test-tamper-relay.mjs [path/to/boxd]
// AB#591: the browser stream library through tee/client/tamper_relay.py, a relay that flips one bit
// on purpose. Starts `boxd -dev -noticket` on loopback. Checks that the flipped frame from the box
// closes the stream with an authentication failure, and that a close which lands before noVNC
// attaches (the c48 case: rfb.js still loading) still reaches the viewer, exactly once.
import { spawn } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import { SealedStream } from './sealed-stream.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const boxd = process.argv[2] || './boxd';
const python = process.env.PYTHON || 'python3';
const te = new TextEncoder();
let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!ok) failures++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const children = [];

const box = spawn(boxd, ['-dev', '-noticket', '-tls', '127.0.0.1:28443', '-stream', '127.0.0.1:28444'], { stdio: ['ignore', 'ignore', 'pipe'] });
children.push(box);
await new Promise((res, rej) => { box.stderr.on('data', (d) => { if (/LISTEN/.test(d.toString())) res(); }); box.on('exit', (c) => rej(new Error(`boxd exited ${c}`))); setTimeout(() => rej(new Error('boxd did not listen')), 5000); });

/** Start the relay on a free port. Resolves to { port, lines }: lines collects what it prints after LISTEN. */
async function relay(...args) {
  const p = spawn(python, [path.join(here, '..', 'client', 'tamper_relay.py'), '--listen', '127.0.0.1:0', '--box', '127.0.0.1:28444', ...args], { stdio: ['ignore', 'pipe', 'inherit'] });
  children.push(p);
  const lines = [];
  const port = await new Promise((res, rej) => {
    readline.createInterface({ input: p.stdout }).on('line', (l) => {
      const m = /^LISTEN \S+:(\d+) /.exec(l);
      if (m) res(Number(m[1])); else lines.push(l);
    });
    p.on('exit', (c) => rej(new Error(`relay exited ${c}`)));
    setTimeout(() => rej(new Error('relay did not listen')), 10000);
  });
  return { port, lines };
}

function tcpPipe(port) {
  const sock = net.connect(port, '127.0.0.1');
  const pipe = { onbytes: null, onclose: null, send: (b) => sock.write(b), close: () => sock.destroy(),
    ready: new Promise((res, rej) => { sock.on('connect', res); sock.on('error', rej); }) };
  sock.on('data', (d) => pipe.onbytes?.(new Uint8Array(d)));
  sock.on('close', () => pipe.onclose?.());
  return pipe;
}

async function until(cond, ms = 5000) { const t = Date.now(); while (!cond() && Date.now() - t < ms) await sleep(20); return cond(); }

try {
  // Box to client, first DATA frame flipped by the relay: the stream must close, not deliver.
  const r = await relay('--direction', 'down', '--frame', '3');
  const pipe = tcpPipe(r.port); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  const got = [];
  s.onmessage = (pt) => got.push(pt);
  const closed = new Promise((res) => { s.onclose = (err) => res(err); });
  s.send(te.encode('JOB 1\n'));
  const err = await Promise.race([closed, sleep(5000).then(() => new Error('no close'))]);
  await until(() => r.lines.length > 0);
  check('relay flipped the box\'s first DATA frame', /^TAMPER flipped down frame 3 /.test(r.lines[0] || ''), r.lines[0]);
  check('flipped frame closes the stream with authentication failed', err?.message === 'authentication failed', err?.message);
  check('nothing was delivered', got.length === 0, `${got.length} delivered`);
} catch (e) { check('tamper down', false, e.message); }

try {
  // The same flip, with nobody listening yet (index.html: rfb.js still importing). When noVNC then
  // attaches through websocketLike(), it must get the close with the reason, once.
  const r = await relay('--direction', 'down', '--frame', '3');
  const pipe = tcpPipe(r.port); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  s.send(te.encode('JOB 1\n'));
  await until(() => s.closed);
  check('stream closed before anyone attached', s.closed === true && s.error?.message === 'authentication failed', s.error?.message);

  const ws = SealedStream.websocketLike(s);
  const closes = [], errors = [];
  ws.onclose = (e) => closes.push(e);                       // noVNC assigns these directly
  ws.onerror = (e) => errors.push(e);
  ws.onmessage = () => {};
  await sleep(50);
  check('the early close reaches noVNC', closes.length === 1 && closes[0].code === 1006 && closes[0].reason === 'authentication failed' && !closes[0].wasClean, JSON.stringify(closes));
  check('with the error first', errors.length === 1 && errors[0].message === 'authentication failed', JSON.stringify(errors));
  check('readyState is closed', ws.readyState === 3, String(ws.readyState));
  ws.onmessage = () => {};                                  // a second attach must not repeat it
  s.close();
  await sleep(50);
  check('the close is delivered once', closes.length === 1, `${closes.length} closes`);
} catch (e) { check('close before attach', false, e.message); }

try {
  // A relay that never reaches its frame is transparent: the bytes it does not touch still work.
  const r = await relay('--frame', '1000');
  const pipe = tcpPipe(r.port); await pipe.ready;
  const s = await SealedStream.open({ pipe, target: 'job', verify: { allowDev: true } });
  const replies = [];
  s.onmessage = (pt) => replies.push(new TextDecoder().decode(pt));
  s.send(te.encode('JOB 7\n'));
  await until(() => replies.length > 0);
  check('untouched frames pass through the relay', replies.join('') === 'DONE 7 42\n', JSON.stringify(replies));
  s.close();
} catch (e) { check('clean relay', false, e.message); }

for (const c of children) c.kill();
console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
