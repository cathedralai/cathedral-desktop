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
    dev: q.get('dev') === '1',
    product: q.get('product') || 'Genoa',
    room: q.get('room') || '',
    kds: q.get('kds') || '',
    certs: q.get('certs') || '',
    ticket: secrets.get('ticket') || '',
    vncpw: secrets.get('vncpw') || '',
  };
}
