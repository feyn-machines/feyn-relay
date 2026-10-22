// The blob endpoint of the Feyn client design, section 6.3: ciphertext files
// kept for one fetch or 24 hours, in the relay's own process. It parses
// nothing but headers and streams bodies to and from disk.
//
//   GET     /feyn/v1/blobs/key        the endpoint's X25519 public key
//   PUT     /feyn/v1/blobs/<address>  store, with a token from an enrolled host
//   GET     /feyn/v1/blobs/<address>  fetch once; deleted when sent whole
//   OPTIONS on both                   CORS for a browser
//
// A file on disk is `<address>.<host id>`: the address is 32 random bytes in
// base64url, made by the host's connector, and is the only thing a fetch
// needs. Size and time are the file's own. Nothing here can open a blob.
import { createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { pipeline } from 'node:stream';

const MiB = 1024 * 1024;
export const LIMITS = {
  blob: 51 * MiB, // one blob: 50 MiB of file plus tags
  host: 500 * MiB, // one host's unfetched blobs; beyond it 413
  total: 2048 * MiB, // all blobs; beyond it 507
  keepMs: 24 * 3600_000, // kept until fetched once, or this long
  sweepMs: 600_000, // a sweep this often, and at start
  aheadS: 900, // a token's expiry is at most this far ahead
};
export const ROOT = '/feyn/v1/blobs';
const ADDRESS = /^[A-Za-z0-9_-]{43}$/;
const HOST = /^[A-Za-z0-9_-]{1,64}$/;
const FILE = /^([A-Za-z0-9_-]{43})\.([A-Za-z0-9_-]{1,64})$/;
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, PUT, OPTIONS',
  'access-control-allow-headers': 'content-type, x-feyn-host, x-feyn-expires, x-feyn-token',
  'access-control-max-age': '600',
};

const publicKeyOf = (x) => createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x }, format: 'jwk' });

// The token of section 6.3:
//   HMAC-SHA256( X25519(host secret key, endpoint public key),
//                "feyn-blob-v1" ‖ 0 ‖ address ‖ 0 ‖ size ‖ 0 ‖ expires )
// with the address as its base64url text and size and expires in decimal.
export function tokenOf(shared, address, size, expires) {
  if (shared.every((b) => b === 0)) throw new Error('low-order key');
  return createHmac('sha256', shared).update(`feyn-blob-v1\0${address}\0${size}\0${expires}`).digest();
}

// The endpoint's key pair, made at first start and kept in the state
// directory. A file that is there but is not a key is never replaced.
function loadKey(path) {
  if (existsSync(path)) {
    const o = JSON.parse(readFileSync(path, 'utf8'));
    if (o?.v !== 1 || typeof o.secretKey !== 'string' || typeof o.publicKey !== 'string') throw new Error(`${path} does not hold a blob endpoint key`);
    return { publicKey: o.publicKey, privateKey: createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: o.secretKey, x: o.publicKey }, format: 'jwk' }) };
  }
  const { privateKey } = generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' });
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(`${path}.tmp`, JSON.stringify({ v: 1, secretKey: jwk.d, publicKey: jwk.x }), { mode: 0o600 });
  renameSync(`${path}.tmp`, path);
  return { publicKey: jwk.x, privateKey };
}

// `hosts` is `relay.hosts`: the enrolled hosts, each `{id, key}` with the
// key in base64url. `request(req, res)` answers true when the request was
// for the blob routes, as `relay.request` does for its own.
export async function createBlobs({ dir, keyFile, hosts, now = Date.now, limits = LIMITS, log = () => {} }) {
  const key = loadKey(keyFile);
  mkdirSync(dir, { recursive: true });
  // address -> {host, size, at, state}: `writing` while an upload is under
  // way, `fetching` while a fetch is, else `kept`.
  const index = new Map();
  for (const name of readdirSync(dir)) {
    const m = FILE.exec(name);
    if (m) {
      const st = statSync(join(dir, name));
      index.set(m[1], { host: m[2], size: st.size, at: st.mtimeMs, state: 'kept' });
    } else if (name.endsWith('.part')) {
      // an upload a restart cut short
      try { unlinkSync(join(dir, name)); } catch { /* gone */ }
    }
  }
  const file = (address, b) => join(dir, `${address}.${b.host}`);
  const drop = (address) => {
    const b = index.get(address);
    if (!b) return;
    index.delete(address);
    try { unlinkSync(file(address, b)); } catch { /* gone */ }
  };

  function usage() {
    const out = { total: 0, hosts: {}, count: 0 };
    for (const b of index.values()) {
      out.total += b.size;
      out.hosts[b.host] = (out.hosts[b.host] ?? 0) + b.size;
      out.count++;
    }
    return out;
  }

  function sweep() {
    let n = 0;
    for (const [address, b] of index) {
      if (b.state === 'kept' && now() - b.at > limits.keepMs) { drop(address); n++; }
    }
    if (n) log(`blob sweep removed=${n}`);
    return n;
  }
  sweep();
  const timer = setInterval(sweep, limits.sweepMs);
  timer.unref();

  const send = (res, status, body, headers = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
    res.end(JSON.stringify(body));
  };

  // Whether the headers carry a token made with an enrolled host's key for
  // this address, this size and an expiry that is still ahead.
  function admitted(req, address, size) {
    const host = req.headers['x-feyn-host'], expires = req.headers['x-feyn-expires'], token = req.headers['x-feyn-token'];
    if (typeof host !== 'string' || typeof expires !== 'string' || typeof token !== 'string') return { status: 401, error: 'a token is needed' };
    const refuse = { status: 403, error: 'the token is not accepted' };
    if (!HOST.test(host) || !/^\d{1,12}$/.test(expires)) return refuse;
    const at = Math.floor(now() / 1000), until = Number(expires);
    if (until < at || until > at + limits.aheadS) return refuse;
    const record = hosts().find((h) => h.id === host);
    if (!record) return refuse;
    try {
      const want = tokenOf(diffieHellman({ privateKey: key.privateKey, publicKey: publicKeyOf(record.key) }), address, size, until);
      const got = Buffer.from(token, 'base64url');
      if (got.length !== want.length || !timingSafeEqual(got, want)) return refuse;
    } catch {
      return refuse;
    }
    return { host };
  }

  function put(req, res, address) {
    const length = req.headers['content-length'];
    if (length === undefined || !/^\d{1,15}$/.test(length)) return send(res, 411, { error: 'content-length is needed' }, { connection: 'close' });
    const size = Number(length);
    // Refused before a byte of the body is read; the connection is closed
    // rather than drained.
    if (size > limits.blob) return send(res, 413, { error: 'over the size of one blob' }, { connection: 'close' });
    // Every other answer comes after the body has been read and dropped, so
    // that a browser sees the status and not a reset connection.
    const answer = (status, body) => { req.resume(); send(res, status, body); };
    const who = admitted(req, address, size);
    if (!who.host) return answer(who.status, { error: who.error });
    if (index.has(address)) return answer(200, { ok: true, existed: true });
    const used = usage();
    if ((used.hosts[who.host] ?? 0) + size > limits.host) { log(`blob put host=${who.host} size=${size} status=413`); return answer(413, { error: 'over this host\'s room' }); }
    if (used.total + size > limits.total) { log(`blob put host=${who.host} size=${size} status=507`); return answer(507, { error: 'no room' }); }

    const b = { host: who.host, size, at: now(), state: 'writing' };
    index.set(address, b);
    const part = `${file(address, b)}.part`;
    let got = 0;
    req.on('data', (d) => { got += d.length; });
    pipeline(req, createWriteStream(part, { flags: 'wx', mode: 0o600 }), (err) => {
      if (err || got !== size) {
        index.delete(address);
        try { unlinkSync(part); } catch { /* never made */ }
        log(`blob put host=${who.host} size=${size} status=${err?.code === 'ENOSPC' ? 507 : 'cut'}`);
        if (!res.headersSent && !res.destroyed) send(res, err?.code === 'ENOSPC' ? 507 : 400, { error: 'the upload did not arrive whole' }, { connection: 'close' });
        return;
      }
      renameSync(part, file(address, b));
      b.state = 'kept';
      b.at = now();
      log(`blob put host=${who.host} size=${size} status=201`);
      send(res, 201, { ok: true });
    });
  }

  function get(req, res, address) {
    const b = index.get(address);
    if (!b || b.state === 'writing') return send(res, 404, { error: 'not found' });
    // One fetch at a time: the first to finish whole removes the blob.
    if (b.state === 'fetching') return send(res, 503, { error: 'being fetched' }, { 'retry-after': '2' });
    let stream;
    try {
      if (statSync(file(address, b)).size !== b.size) throw new Error('changed');
      stream = createReadStream(file(address, b));
    } catch {
      drop(address);
      return send(res, 404, { error: 'not found' });
    }
    b.state = 'fetching';
    res.writeHead(200, { 'content-type': 'application/octet-stream', 'content-length': String(b.size), 'cache-control': 'no-store' });
    pipeline(stream, res, (err) => {
      if (err) { b.state = 'kept'; log(`blob get host=${b.host} size=${b.size} status=cut`); return; }
      drop(address);
      log(`blob get host=${b.host} size=${b.size} status=200`);
    });
  }

  async function request(req, res) {
    const path = new URL(req.url ?? '/', 'http://relay').pathname;
    if (path !== ROOT && !path.startsWith(`${ROOT}/`)) return false;
    for (const [k, v] of Object.entries(CORS)) res.setHeader(k, v);
    const name = path.slice(ROOT.length + 1);
    try {
      if (req.method === 'OPTIONS') res.writeHead(204).end();
      else if (name === 'key') {
        if (req.method === 'GET') send(res, 200, { key: key.publicKey }); else send(res, 405, { error: 'method not allowed' });
      } else if (!ADDRESS.test(name)) send(res, 404, { error: 'not found' });
      else if (req.method === 'PUT') put(req, res, name);
      else if (req.method === 'GET') get(req, res, name);
      else send(res, 405, { error: 'method not allowed' });
    } catch (e) {
      log(`blob error=${String(e?.message ?? e)}`);
      if (!res.headersSent) send(res, 500, { error: 'internal' }); else res.destroy();
    }
    return true;
  }

  return { publicKey: key.publicKey, request, sweep, usage, close: () => clearInterval(timer) };
}
