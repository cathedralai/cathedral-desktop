// node tee/web/test-link.mjs
// Which part of the page link carries what. The single-use ticket and the desktop password come from
// the fragment, which the browser never sends to a server or a relay and keeps out of Referer headers;
// everything else comes from the query.
import { readLink } from './link.js';

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

console.log(failures ? `${failures} failure(s)` : 'all checks passed');
process.exit(failures ? 1 : 0);
