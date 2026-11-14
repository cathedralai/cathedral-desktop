// node tee/web/test-link.mjs
// Which part of the page link carries what. The single-use ticket and the desktop password come from
// the fragment, which the browser never sends to a server or a relay and keeps out of Referer headers;
// everything else comes from the query.
import * as linkModule from './link.js';

const { readLink } = linkModule;

let failures = 0;
const check = (name, ok, detail = '') => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? '  ' + detail : ''}`); if (!ok) failures++; };
const loc = (search, hash = '') => ({ search, hash, protocol: 'https:', host: 'view.example' });

const t = 'eyJhIjoxfQ.c2ln-_x';
let l = readLink(loc('?target=vnc', `#ticket=${t}&vncpw=hunter2`));
check('ticket is read from the fragment', l.ticket === t, l.ticket);
check('desktop password is read from the fragment', l.vncpw === 'hunter2', l.vncpw);

l = readLink(loc(`?target=vnc&ticket=${t}&vncpw=hunter2`));
check('a ticket in the query is ignored', l.ticket === '', JSON.stringify(l.ticket));
check('a desktop password in the query is ignored', l.vncpw === '', JSON.stringify(l.vncpw));

l = readLink(loc('?ticket=fromquery&vncpw=fromquery', '#ticket=fromfragment&vncpw=fromfragment'));
check('the fragment wins when both carry a ticket', l.ticket === 'fromfragment', l.ticket);
check('the fragment wins when both carry a password', l.vncpw === 'fromfragment', l.vncpw);

l = readLink(loc('?relay=wss://r.example/ws&target=job&fp=AB, cd&room=0123456789&nofp=1', `#ticket=${t}`));
check('other settings still come from the query', l.relay === 'wss://r.example/ws' && l.target === 'job' && l.room === '0123456789' && l.nofp === true);
check('fingerprints are trimmed and lower-cased', JSON.stringify(l.allowed) === '["ab","cd"]', JSON.stringify(l.allowed));

l = readLink(loc('', ''));
check('defaults: vnc, a relay on the page host, no fingerprint, no ticket',
  l.target === 'vnc' && l.relay === 'wss://view.example/websockify' && l.allowed.length === 0 && l.ticket === '' && l.nofp === false);

// A ticket or password in the query is not read as one. link.js reports the link as misplaced, which is what
// lets the page refuse it and say where the ticket belongs; these checks cover that report and nothing more.
l = readLink(loc(`?target=vnc&ticket=${t}`));
check('a ticket in the query is reported as misplaced', JSON.stringify(l.misplaced) === '["ticket"]', JSON.stringify(l.misplaced));
l = readLink(loc('?vncpw=x&ticket=y&target=vnc'));
check('both secrets in the query are reported', JSON.stringify([...(l.misplaced || [])].sort()) === '["ticket","vncpw"]', JSON.stringify(l.misplaced));
l = readLink(loc('?target=vnc', `#ticket=${t}`));
check('nothing is misplaced when the secrets are in the fragment', Array.isArray(l.misplaced) && l.misplaced.length === 0, JSON.stringify(l.misplaced));
const cleaned = linkModule.cleanSearch?.(`?relay=wss://r/ws&ticket=${t}&target=job&vncpw=x`);
check('the query without secrets keeps every other setting', cleaned === '?relay=wss%3A%2F%2Fr%2Fws&target=job', String(cleaned));
check('an empty query stays empty', linkModule.cleanSearch?.('') === '', String(linkModule.cleanSearch?.('')));
const prob = linkModule.linkProblem?.(readLink(loc(`?ticket=${t}&fp=ab`)));
check('a misplaced ticket is a problem that points at the #', !!prob && /#/.test(prob.why) && /ticket/.test(prob.why), JSON.stringify(prob));

// No fingerprint choice: the library's refusal is for developers, so the page words its own for the link holder.
let noFp = linkModule.linkProblem?.(readLink(loc('?target=vnc')));
check('no fp= and no nofp=1 is a problem that names both link parts', !!noFp && /fp=/.test(noFp.why) && /nofp=1/.test(noFp.why), JSON.stringify(noFp));
check('fp= alone is fine', linkModule.linkProblem?.(readLink(loc('?fp=ab'))) === null);
check('nofp=1 alone is fine', linkModule.linkProblem?.(readLink(loc('?nofp=1'))) === null);

// Hosted-page label (plan S7): the page always says who serves it. Loopback gets it too: the runbook reaches
// the relay's page through an SSH tunnel, so a loopback origin does not mean the page is local. A hostile
// server can delete the label, so it never carries the privacy promise.
import { readFileSync } from 'node:fs';
const at = (protocol, host, search = '') => {
  const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.replace(/:\d+$/, '');
  return { search, hash: '', protocol, host, hostname, origin: `${protocol}//${host}` };
};
const LABEL = (origin) => `Loaded from ${origin}. Whoever serves this page, even through a tunnel, can see your screen.`;
const label = (l) => linkModule.hostedLabel?.(l);
for (const [proto, host, name] of [
  ['https:', 'example.test', 'https://example.test'],
  ['https:', 'example.test:8443', 'https://example.test with a port'],
  ['http:', '10.1.2.3:8080', 'an IP that is not loopback'],
  ['https:', 'localhost.example.test', 'a name that starts with localhost.'],
  ['https:', '127.0.0.1.example.test', 'a name that starts with 127.'],
  ['http:', '127.0.0.1:8080', '127.0.0.1'],
  ['http:', 'localhost:8080', 'localhost'],
  ['http:', '[::1]:8080', '[::1]'],
]) {
  const got = label(at(proto, host));
  check(`label names the origin on ${name}`, got === LABEL(`${proto}//${host}`), String(got));
}
check('no link parameter changes or hides the label',
  ['?label=0', '?hosted=0&nolabel=1&hidelabel=1', '?relay=wss://r.example/ws&fp=ab&nofp=1&dev=1'].every((q) => label(at('https:', 'example.test', q)) === LABEL('https://example.test')));
const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');

// What is wrong with the label in this page source: markup, style rules, and script. [] when nothing is.
function hostedProblems(src) {
  const problems = [];
  const tag = src.match(/<[^>]*id="hosted"[^>]*>/)?.[0] || '';
  if (!tag) problems.push('no #hosted element');
  if (/\bhidden\b|\baria-hidden\b|\bstyle=/.test(tag)) problems.push('hidden or styled by attribute: ' + tag);
  const main = src.match(/<main[\s\S]*?<\/main>/)?.[0] || '';
  if (/id="hosted"/.test(main)) problems.push('#hosted is inside <main>, where #gone can cover it');
  const css = src.match(/<style>([\s\S]*?)<\/style>/)?.[1] || '';
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ sel: m[1].trim(), body: m[2] }));
  const decl = (body, prop) => [...body.matchAll(new RegExp(`(?:^|;|\\s)${prop}\\s*:\\s*([^;]+)`, 'g'))].map((m) => m[1].trim().toLowerCase());
  const own = rules.filter((r) => r.sel.split(',').some((x) => /#hosted\b/.test(x)));
  const wide = rules.filter((r) => r.sel.split(',').some((x) => ['*', 'div', 'body', '[role=note]', '[role="note"]'].includes(x.trim())));
  for (const r of [...own, ...wide]) {
    for (const v of decl(r.body, 'display')) if (v.startsWith('none')) problems.push('display:none in ' + r.sel);
    for (const v of decl(r.body, 'visibility')) if (v !== 'visible') problems.push('visibility in ' + r.sel);
    for (const v of decl(r.body, 'opacity')) if (parseFloat(v) < 0.9) problems.push('opacity in ' + r.sel);
    for (const p of ['height', 'max-height', 'font-size', 'width', 'max-width']) for (const v of decl(r.body, p)) if (/^0(px|em|rem|%)?$/.test(v)) problems.push(p + ':0 in ' + r.sel);
    for (const p of ['left', 'right', 'top', 'bottom', 'text-indent', 'margin-left', 'margin-top']) for (const v of decl(r.body, p)) if (/^-/.test(v)) problems.push(p + ' pushes it off screen in ' + r.sel);
    for (const p of ['clip', 'clip-path', 'transform', 'filter', 'content-visibility']) if (decl(r.body, p).length) problems.push(p + ' in ' + r.sel);
    for (const v of decl(r.body, 'color')) if (v === 'transparent' || v === 'var(--bg)' || v === '#000') problems.push('color hides the text in ' + r.sel);
    for (const v of decl(r.body, 'overflow')) if (v === 'hidden' && /#hosted/.test(r.sel)) problems.push('overflow:hidden clips a long origin in ' + r.sel);
  }
  const mine = own.map((r) => r.body).join(';');
  if (!decl(mine, 'position').includes('relative')) problems.push('#hosted is not positioned, so #gone paints over it');
  const z = Math.max(...decl(mine, 'z-index').map(Number), -Infinity);
  const goneZ = Math.max(...rules.filter((r) => /\.note|#gone/.test(r.sel)).flatMap((r) => decl(r.body, 'z-index').map(Number)), 0);
  if (!(z > goneZ)) problems.push(`#hosted z-index ${z} is not above #gone's ${goneZ}`);
  if (!decl(mine, 'overflow-wrap').some((v) => v === 'anywhere' || v === 'break-word')) problems.push('no wrap rule for a long origin');
  const script = src.slice(src.indexOf('<script type="module">'));
  if ((script.match(/getElementById\('hosted'\)/g) || []).length !== 1) problems.push('the script touches #hosted other than to set its text');
  if (/getElementById\('hosted'\)\.(hidden|style|remove|classList|setAttribute)/.test(script)) problems.push('the script changes #hosted');
  return problems;
}
check('the label is in the page, in view, wraps, and #gone cannot cover it', hostedProblems(html).length === 0, hostedProblems(html).join('; '));
const mutate = (from, to) => html.replace(from, to);
const hostedRule = html.match(/#hosted \{[^}]*\}/)[0];
for (const [name, bad, why] of [
  ['display:none in the style rules', mutate(hostedRule, hostedRule.replace('{', '{ display: none;')), /display:none/],
  ['visibility:hidden in the style rules', mutate(hostedRule, hostedRule.replace('{', '{ visibility: hidden;')), /visibility/],
  ['opacity 0 in the style rules', mutate(hostedRule, hostedRule.replace('{', '{ opacity: 0;')), /opacity/],
  ['height 0 in the style rules', mutate(hostedRule, hostedRule.replace('{', '{ height: 0;')), /height:0/],
  ['an off-screen position in the style rules', mutate(hostedRule, hostedRule.replace('{', '{ left: -9999px;')), /off screen/],
  ['text the colour of the background', mutate(hostedRule, hostedRule.replace('{', '{ color: transparent;')), /hides the text/],
  ['no z-index above #gone', mutate(hostedRule, hostedRule.replace(/z-index:[^;]*;/, '')), /z-index/],
  ['no wrap rule', mutate(hostedRule, hostedRule.replace(/overflow-wrap:[^;]*;/, '')), /wrap rule/],
  ['a hidden attribute', mutate('<div id="hosted"', '<div id="hosted" hidden'), /hidden/],
  ['the label inside <main>', mutate('<main>', '<main><div id="hosted"></div>'), /inside <main>/],
  ['a script that hides it', mutate("getElementById('hosted').textContent", "getElementById('hosted').hidden = true; document.getElementById('hosted').textContent"), /hides it|changes #hosted/],
]) check(`the label check catches ${name}`, hostedProblems(bad).some((p) => why.test(p)), hostedProblems(bad).join('; '));
const script = html.slice(html.indexOf('<script type="module">'));
const setAt = script.indexOf('hostedLabel(');
const connectAt = Math.min(...['await ', 'websocketPipe(', 'SealedStream.open('].map((k) => { const n = script.indexOf(k, script.indexOf('readLink(location)')); return n < 0 ? Infinity : n; }));
check('the label is set before the page awaits or connects to anything', setAt > 0 && setAt < connectAt, `label at ${setAt}, first connect step at ${connectAt}`);

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
