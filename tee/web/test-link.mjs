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

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
