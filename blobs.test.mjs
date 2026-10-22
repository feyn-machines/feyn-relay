// The blob endpoint of the client design, section 6.3, on loopback: who may
// upload, the size a token names, one fetch, the three limits, the sweep.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, utimesSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBlobs, LIMITS } from './blobs.mjs';

const MiB = 1024 * 1024;
const b64u = (b) => Buffer.from(b).toString('base64url');

// A host as the relay knows one: an X25519 key pair; the record holds the
// public half, and the id is whatever the relay says it is.
function makeHost(id) {
  const { privateKey, publicKey } = generateKeyPairSync('x25519');
  const jwk = privateKey.export({ format: 'jwk' });
  return { id, record: { id, key: jwk.x, name: id, added: 0 }, privateKey, publicKey };
}
// The token exactly as section 6.3 writes it, computed here without the
// endpoint's own code.
function token(host, endpointKey, address, size, expires) {
  const shared = diffieHellman({ privateKey: host.privateKey, publicKey: createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: endpointKey }, format: 'jwk' }) });
  const zero = Buffer.alloc(1);
  return createHmac('sha256', shared).update(Buffer.concat([Buffer.from('feyn-blob-v1'), zero, Buffer.from(address), zero, Buffer.from(String(size)), zero, Buffer.from(String(expires))])).digest('base64url');
}

async function setup(t, o = {}) {
  const run = mkdtempSync(join(tmpdir(), 'feyn-blobs-'));
  const clock = { ms: Date.parse('2026-10-12T09:00:00Z') };
  const hosts = [makeHost('hostAAAAAAAAAAAAAAAAAA'), makeHost('hostBBBBBBBBBBBBBBBBBB')];
  const enrolled = hosts.map((h) => h.record);
  const lines = [];
  const blobs = await createBlobs({ dir: join(run, 'blobs'), keyFile: join(run, 'state', 'blob-key.json'), hosts: () => enrolled, now: () => clock.ms, log: (l) => lines.push(l), ...o });
  const server = createServer((req, res) => { void blobs.request(req, res).then((ours) => { if (!ours) res.writeHead(404).end('not ours'); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  t.after(async () => { blobs.close(); server.closeAllConnections(); await new Promise((r) => server.close(r)); rmSync(run, { recursive: true, force: true }); });

  // One request; `body` a Buffer; `cut` closes the connection at the first bytes of the answer.
  const call = (method, path, { headers = {}, body, cut } = {}) => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: { ...(body ? { 'content-length': body.length } : {}), ...headers } }, (res) => {
      const chunks = [];
      if (cut) { res.once('data', () => { res.destroy(); resolve({ status: res.statusCode, cut: true }); }); return; }
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(body);
  });
  const key = JSON.parse((await call('GET', '/feyn/v1/blobs/key')).body).key;
  const seconds = () => Math.floor(clock.ms / 1000);
  const address = () => b64u(randomBytes(32));
  // The headers a host's connector hands to a device for one upload.
  const grant = (host, addr, size, expires = seconds() + 600) => ({ 'x-feyn-host': host.id, 'x-feyn-expires': String(expires), 'x-feyn-token': token(host, key, addr, size, expires) });
  const put = (host, addr, body, over = {}) => call('PUT', `/feyn/v1/blobs/${addr}`, { body, headers: { ...grant(host, addr, body.length), ...over } });
  // A fetch. The endpoint removes a blob once the whole answer has left it,
  // which is a moment after the last byte arrives here: a whole fetch waits
  // for the endpoint's own line saying so.
  const get = async (addr, o) => {
    const before = lines.filter((l) => l.startsWith('blob get')).length;
    const r = await call('GET', `/feyn/v1/blobs/${addr}`, o);
    if (r.status === 200 || r.cut) for (let i = 0; i < 500 && lines.filter((l) => l.startsWith('blob get')).length === before; i++) await new Promise((res) => setTimeout(res, 10));
    return r;
  };
  return { run, port, clock, hosts, enrolled, blobs, call, key, seconds, address, grant, put, get, lines, dir: join(run, 'blobs') };
}

test('the key is made once, kept privately in the state directory, and served', async (t) => {
  const s = await setup(t);
  assert.match(s.key, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(s.blobs.publicKey, s.key);
  const file = join(s.run, 'state', 'blob-key.json');
  assert.equal(statSync(file).mode & 0o777, 0o600);
  const again = await createBlobs({ dir: s.dir, keyFile: file, hosts: () => [] });
  assert.equal(again.publicKey, s.key);
  again.close();
});

test('a token made with an enrolled host\'s key admits one upload of one size, fetched once', async (t) => {
  const s = await setup(t);
  const [a] = s.hosts;
  const addr = s.address(), body = randomBytes(3 * MiB + 17);
  const r = await s.put(a, addr, body);
  assert.equal(r.status, 201);
  assert.equal(r.headers['access-control-allow-origin'], '*');
  // What is kept: ciphertext under the address, with the host's id.
  assert.deepEqual(readdirSync(s.dir), [`${addr}.${a.id}`]);
  assert.ok(readFileSync(join(s.dir, `${addr}.${a.id}`)).equals(body));
  assert.deepEqual(s.blobs.usage(), { total: body.length, hosts: { [a.id]: body.length }, count: 1 });
  const g = await s.get(addr);
  assert.equal(g.status, 200);
  assert.equal(g.headers['content-length'], String(body.length));
  assert.equal(g.headers['access-control-allow-origin'], '*');
  assert.ok(g.body.equals(body));
  // Deleted when the response has been sent whole.
  assert.equal((await s.get(addr)).status, 404);
  assert.deepEqual(readdirSync(s.dir), []);
  assert.deepEqual(s.blobs.usage(), { total: 0, hosts: {}, count: 0 });
  // The log names the host and the size, never the address.
  assert.ok(s.lines.some((l) => l.includes('put') && l.includes(a.id) && l.includes(String(body.length))), s.lines.join('\n'));
  assert.ok(!s.lines.some((l) => l.includes(addr)));
});

test('an empty blob can be stored and fetched', async (t) => {
  const s = await setup(t);
  const addr = s.address();
  const r = await s.call('PUT', `/feyn/v1/blobs/${addr}`, { headers: { 'content-length': '0', ...s.grant(s.hosts[0], addr, 0) } });
  assert.equal(r.status, 201);
  const g = await s.get(addr);
  assert.equal(g.status, 200);
  assert.equal(g.body.length, 0);
});

test('uploads are refused without a good token', async (t) => {
  const s = await setup(t);
  const [a, b] = s.hosts;
  const body = randomBytes(1000);
  const refused = async (what, status, fn) => {
    const addr = s.address();
    const r = await fn(addr);
    assert.equal(r.status, status, what);
    assert.equal((await s.get(addr)).status, 404, `${what}: nothing stored`);
  };
  await refused('no headers', 401, (addr) => s.call('PUT', `/feyn/v1/blobs/${addr}`, { body }));
  // B's id with a token made by A's key.
  await refused('wrong host', 403, (addr) => s.put(a, addr, body, { 'x-feyn-host': b.id }));
  const stranger = makeHost('hostCCCCCCCCCCCCCCCCCC');
  await refused('a host that is not enrolled', 403, (addr) => s.put(stranger, addr, body));
  await refused('a token for another address', 403, (addr) => s.put(a, addr, body, s.grant(a, s.address(), body.length)));
  await refused('a token for another size', 403, (addr) => s.put(a, addr, body, s.grant(a, addr, body.length + 1)));
  await refused('a changed expiry', 403, (addr) => s.put(a, addr, body, { 'x-feyn-expires': String(s.seconds() + 601) }));
  await refused('expired', 403, (addr) => s.put(a, addr, body, s.grant(a, addr, body.length, s.seconds() - 1)));
  await refused('more than 15 minutes ahead', 403, (addr) => s.put(a, addr, body, s.grant(a, addr, body.length, s.seconds() + 901)));
  await refused('a token that is not base64url', 403, (addr) => s.put(a, addr, body, { 'x-feyn-token': '!!!' }));
  await refused('an expiry that is not a number', 403, (addr) => s.put(a, addr, body, { 'x-feyn-expires': 'soon' }));
  assert.equal((await s.call('PUT', '/feyn/v1/blobs/short', { body, headers: s.grant(a, 'short', body.length) })).status, 404);
  assert.equal((await s.call('PUT', `/feyn/v1/blobs/${s.address()}`, { headers: { ...s.grant(a, 'x', 0), 'transfer-encoding': 'chunked' }, body: undefined })).status, 411);
  assert.deepEqual(readdirSync(s.dir), []);

  // A token is good until its own expiry and no longer.
  const addr = s.address(), grant = s.grant(a, addr, body.length);
  s.clock.ms += 601_000;
  assert.equal((await s.call('PUT', `/feyn/v1/blobs/${addr}`, { body, headers: grant })).status, 403);

  // A revoked host's tokens stop at once.
  const addr2 = s.address(), grant2 = s.grant(b, addr2, body.length);
  s.enrolled.splice(s.enrolled.indexOf(b.record), 1);
  assert.equal((await s.call('PUT', `/feyn/v1/blobs/${addr2}`, { body, headers: grant2 })).status, 403);
  assert.equal((await s.put(a, s.address(), body)).status, 201);
});

test('a blob over 51 MiB is refused before its body is read', async (t) => {
  const s = await setup(t);
  const [a] = s.hosts;
  assert.equal(LIMITS.blob, 51 * MiB);
  const addr = s.address(), size = 51 * MiB + 1;
  const res = await s.call('PUT', `/feyn/v1/blobs/${addr}`, { headers: { 'content-length': String(size), ...s.grant(a, addr, size) }, body: undefined }).catch((e) => ({ status: 0, error: e }));
  assert.equal(res.status, 413);
  assert.deepEqual(readdirSync(s.dir), []);
});

test('exactly 51 MiB is accepted', async (t) => {
  const s = await setup(t);
  const addr = s.address(), body = Buffer.alloc(51 * MiB, 7);
  assert.equal((await s.put(s.hosts[0], addr, body)).status, 201);
  assert.equal(statSync(join(s.dir, `${addr}.${s.hosts[0].id}`)).size, 51 * MiB);
});

test('a second PUT of an address is answered 200 and changes nothing', async (t) => {
  const s = await setup(t);
  const [a] = s.hosts;
  const addr = s.address(), first = Buffer.alloc(2000, 1), second = Buffer.alloc(2000, 2);
  assert.equal((await s.put(a, addr, first)).status, 201);
  assert.equal((await s.put(a, addr, second)).status, 200);
  assert.equal(s.blobs.usage().total, 2000);
  assert.ok((await s.get(addr)).body.equals(first));
});

test('a fetch cut halfway keeps the blob; a whole one removes it', async (t) => {
  const s = await setup(t);
  const addr = s.address(), body = Buffer.alloc(40 * MiB, 9);
  assert.equal((await s.put(s.hosts[0], addr, body)).status, 201);
  const cut = await s.get(addr, { cut: true });
  assert.equal(cut.cut, true);
  // The endpoint has noticed the closed connection: the blob is there again.
  assert.ok(s.lines.at(-1).endsWith('status=cut'), s.lines.at(-1));
  assert.equal(s.blobs.usage().count, 1);
  const whole = await s.get(addr);
  assert.equal(whole.status, 200);
  assert.equal(whole.body.length, body.length);
  assert.equal((await s.get(addr)).status, 404);
});

test('while one fetch is under way a second is told to come back', async (t) => {
  const s = await setup(t);
  const addr = s.address(), body = Buffer.alloc(40 * MiB, 3);
  assert.equal((await s.put(s.hosts[0], addr, body)).status, 201);
  // The second request is made when the first answer's headers are here.
  let second;
  const done = await new Promise((resolve, reject) => {
    request({ host: '127.0.0.1', port: s.port, path: `/feyn/v1/blobs/${addr}` }, (res) => {
      second = s.call('GET', `/feyn/v1/blobs/${addr}`);
      let n = 0;
      res.on('data', (d) => { n += d.length; });
      res.on('end', () => resolve({ status: res.statusCode, length: n }));
    }).on('error', reject).end();
  });
  assert.deepEqual(done, { status: 200, length: body.length });
  const r = await second;
  assert.equal(r.status, 503);
  assert.equal(r.headers['retry-after'], '2');
});

test('one host\'s unfetched blobs are capped (413) and so are all blobs (507)', async (t) => {
  const s = await setup(t, { limits: { ...LIMITS, host: 5000, total: 7000 } });
  const [a, b] = s.hosts;
  const first = s.address();
  assert.equal((await s.put(a, first, Buffer.alloc(3000))).status, 201);
  assert.equal((await s.put(a, s.address(), Buffer.alloc(2000))).status, 201);
  const over = s.address();
  assert.equal((await s.put(a, over, Buffer.alloc(1))).status, 413);
  assert.equal((await s.get(over)).status, 404);
  assert.equal((await s.put(b, s.address(), Buffer.alloc(2000))).status, 201);
  assert.equal((await s.put(b, s.address(), Buffer.alloc(1))).status, 507);
  // A fetch frees the room.
  assert.equal((await s.get(first)).status, 200);
  assert.equal((await s.put(a, s.address(), Buffer.alloc(3000))).status, 201);
  assert.equal(s.blobs.usage().total, 7000);
  assert.equal(LIMITS.host, 500 * MiB);
  assert.equal(LIMITS.total, 2048 * MiB);
});

test('the sweep removes what is older than 24 hours, and a restart finds what is on disk', async (t) => {
  const s = await setup(t);
  const [a, b] = s.hosts;
  const old = s.address(), young = s.address();
  assert.equal((await s.put(a, old, Buffer.alloc(100))).status, 201);
  s.clock.ms += 23 * 3600_000;
  assert.equal((await s.put(b, young, Buffer.alloc(200))).status, 201);
  assert.equal(s.blobs.sweep(), 0);
  s.clock.ms += 3600_000 + 1000;
  assert.equal(s.blobs.sweep(), 1);
  assert.deepEqual(readdirSync(s.dir), [`${young}.${b.id}`]);
  assert.equal((await s.get(old)).status, 404);
  assert.equal(LIMITS.keepMs, 24 * 3600_000);
  assert.equal(LIMITS.sweepMs, 600_000);

  // A second endpoint over the same directory: the index is the directory,
  // and a blob's time is its file's (set here to the fake clock's).
  const uploaded = new Date(s.clock.ms - 3601_000);
  utimesSync(join(s.dir, `${young}.${b.id}`), uploaded, uploaded);
  const again = await createBlobs({ dir: s.dir, keyFile: join(s.run, 'state', 'blob-key.json'), hosts: () => s.enrolled, now: () => s.clock.ms });
  assert.deepEqual(again.usage(), { total: 200, hosts: { [b.id]: 200 }, count: 1 });
  again.close();
  // And it sweeps at start: a day later nothing is left.
  s.clock.ms += 24 * 3600_000;
  const later = await createBlobs({ dir: s.dir, keyFile: join(s.run, 'state', 'blob-key.json'), hosts: () => s.enrolled, now: () => s.clock.ms });
  assert.deepEqual(readdirSync(s.dir), []);
  later.close();
});

test('an upload that stops short leaves nothing', async (t) => {
  const s = await setup(t);
  const [a] = s.hosts;
  const addr = s.address();
  await new Promise((resolve) => {
    const req = request({ host: '127.0.0.1', port: s.port, method: 'PUT', path: `/feyn/v1/blobs/${addr}`, headers: { 'content-length': '5000', ...s.grant(a, addr, 5000) } });
    req.on('error', () => resolve());
    req.on('close', () => resolve());
    req.write(Buffer.alloc(1000), () => setTimeout(() => req.destroy(), 30));
  });
  for (let i = 0; i < 100 && readdirSync(s.dir).length; i++) await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(readdirSync(s.dir), []);
  assert.deepEqual(s.blobs.usage(), { total: 0, hosts: {}, count: 0 });
  assert.equal((await s.get(addr)).status, 404);
});

test('OPTIONS answers a browser\'s preflight; other paths are not ours', async (t) => {
  const s = await setup(t);
  for (const path of ['/feyn/v1/blobs/key', `/feyn/v1/blobs/${s.address()}`]) {
    const r = await s.call('OPTIONS', path, { headers: { origin: 'https://app.example', 'access-control-request-method': 'PUT', 'access-control-request-headers': 'x-feyn-host,x-feyn-expires,x-feyn-token' } });
    assert.equal(r.status, 204);
    assert.equal(r.headers['access-control-allow-origin'], '*');
    assert.match(r.headers['access-control-allow-methods'], /PUT/);
    for (const h of ['x-feyn-host', 'x-feyn-expires', 'x-feyn-token']) assert.ok(r.headers['access-control-allow-headers'].includes(h), h);
  }
  assert.equal((await s.call('GET', '/relay/v1/hosts')).body.toString(), 'not ours');
  assert.equal((await s.call('GET', '/feyn/v1/blobsX')).body.toString(), 'not ours');
  assert.equal((await s.call('POST', `/feyn/v1/blobs/${s.address()}`)).status, 405);
  assert.equal((await s.call('GET', '/feyn/v1/blobs/..%2F..%2Fstate%2Fblob-key.json')).status, 404);
  assert.equal(existsSync(join(s.run, 'state', 'blob-key.json')), true);
});
