// The relay's statement (relay distribution design, section 3): that this
// relay's domain is one of the owner's relays, signed with the package key.
// The owner makes both files with `sign-relay DOMAIN` and puts them in the
// state directory; a machine fetches them and checks them before it joins or
// connects. This process only serves them and checks nothing: the bytes are
// sent exactly as stored, since the signature is over those bytes.
//
//   GET|HEAD /feyn/v1/relay        relay-statement.json      application/json
//   GET|HEAD /feyn/v1/relay.sig    relay-statement.json.sig  application/octet-stream
//
// Both are read again on every request, so a renewed statement is served
// without a restart. A missing file is 404.
import { readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const FILE = 'relay-statement.json';
const ROUTES = {
  '/feyn/v1/relay': { file: FILE, type: 'application/json' },
  '/feyn/v1/relay.sig': { file: `${FILE}.sig`, type: 'application/octet-stream' },
};

export function createStatement({ dir }) {
  // Answers true when the request was this module's.
  async function request(req, res) {
    const route = ROUTES[new URL(req.url ?? '/', 'http://relay').pathname];
    if (!route) return false;
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'application/json', allow: 'GET, HEAD' }).end(JSON.stringify({ error: 'method' }));
      return true;
    }
    let bytes;
    try { bytes = await readFile(join(dir, route.file)); } catch {
      res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'not found' }));
      return true;
    }
    res.writeHead(200, { 'content-type': route.type, 'content-length': bytes.length, 'cache-control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : bytes);
    return true;
  }

  // The line logged at start: what a machine will find here.
  function describe() {
    let s;
    try {
      readFileSync(join(dir, `${FILE}.sig`));
      s = readFileSync(join(dir, FILE), 'utf8');
    } catch { return 'statement: missing, machines will refuse this relay'; }
    try {
      const o = JSON.parse(s);
      if (typeof o?.relay !== 'string' || typeof o?.expires !== 'string') throw new Error('fields');
      return `statement: ${o.relay} until ${o.expires}`;
    } catch { return 'statement: unreadable, machines will refuse this relay'; }
  }

  return { request, describe };
}
