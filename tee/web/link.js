// Reads the page's link into one plain object, so the rules about which part of the link carries what
// live in one place that a test can reach without a browser.

/** @param {{search: string, hash: string, protocol: string, host: string}} loc a Location, or anything shaped like one */
export function readLink(loc) {
  const q = new URLSearchParams(loc.search);
  // Secrets only from the fragment: a query string reaches the relay's access log and Referer headers.
  const secrets = new URLSearchParams(loc.hash.replace(/^#/, ''));
  return {
    relay: q.get('relay') || ((loc.protocol === 'https:' ? 'wss://' : 'ws://') + loc.host + '/websockify'),
    target: q.get('target') || 'vnc',
    allowed: (q.get('fp') || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
    nofp: q.get('nofp') === '1',
    product: q.get('product') || 'Genoa',
    room: q.get('room') || '',
    kds: q.get('kds') || '',
    certs: q.get('certs') || '',
    ticket: secrets.get('ticket') || '',
    vncpw: secrets.get('vncpw') || '',
    misplaced: ['ticket', 'vncpw'].filter((k) => q.has(k)),
  };
}

/** The query with the secrets taken out, for the address bar. */
export function cleanSearch(search) {
  const q = new URLSearchParams(search);
  q.delete('ticket');
  q.delete('vncpw');
  const s = q.toString();
  return s ? '?' + s : '';
}

/** What is wrong with this link for the person holding it, as {title, why, detail}, or null when nothing is. */
export function linkProblem(link) {
  if (link.misplaced.length) {
    return {
      title: 'Link not accepted',
      why: `This link has the ${link.misplaced.join(' and ')} before the "?" part. It must come after a "#" instead (...#ticket=...), `
        + 'so it never reaches the relay or its logs. The one in this link was removed from the address bar and not used; ask for a new link.',
      detail: `misplaced: ${link.misplaced.join(', ')}`,
    };
  }
  return null;
}
