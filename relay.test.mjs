// The mount file as it is deployed, run as a child on loopback: the blob
// routes, the relay's own routes and the WebSocket upgrade share one port.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, request } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const freePort = () => new Promise((resolve) => { const s = createServer(); s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)); }); });

async function start(t, env) {
  const run = mkdtempSync(join(tmpdir(), 'feyn-relay-'));
  // The state directory is a mounted volume where this is deployed.
  mkdirSync(join(run, 'state'));
  const port = await freePort();
  const out = [];
  const child = spawn(process.execPath, [join(import.meta.dirname, 'relay.mjs')], {
    env: { PATH: process.env.PATH, RELAY_PORT: String(port), RELAY_STATE: join(run, 'state', 'relay.json'), RELAY_OWNER_TOKEN: 'owner-token-for-this-test', ...env(run) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  child.stdout.on('data', (d) => out.push(String(d)));
  child.stderr.on('data', (d) => out.push(String(d)));
  t.after(async () => { await new Promise((r) => { child.once('exit', r); child.kill('SIGTERM'); }); rmSync(run, { recursive: true, force: true }); });
  for (let i = 0; i < 400 && !out.join('').includes('relay listening'); i++) await new Promise((r) => setTimeout(r, 25));
  assert.ok(out.join('').includes('relay listening'), out.join(''));
  const call = (method, path, headers = {}) => new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers }, (res) => {
      let body = '';
      res.on('data', (d) => { body += d; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('upgrade', (res, socket) => { socket.destroy(); resolve({ status: res.statusCode, upgraded: true }); });
    req.on('error', reject);
    req.end();
  });
  return { run, port, call, out };
}
const upgrade = { connection: 'Upgrade', upgrade: 'websocket', 'sec-websocket-version': '13', 'sec-websocket-key': Buffer.alloc(16, 1).toString('base64') };

test('blobs first, then the relay, then 404; upgrades go to the relay', async (t) => {
  const s = await start(t, (run) => ({ BLOB_DIR: join(run, 'blobs') }));
  const key = await s.call('GET', '/feyn/v1/blobs/key');
  assert.equal(key.status, 200);
  assert.match(JSON.parse(key.body).key, /^[A-Za-z0-9_-]{43}$/);
  // The key pair is kept beside the relay's state; blobs in their own place.
  assert.ok(existsSync(join(s.run, 'state', 'blob-key.json')));
  assert.ok(existsSync(join(s.run, 'blobs')));
  assert.equal((await s.call('GET', `/feyn/v1/blobs/${'A'.repeat(43)}`)).status, 404);
  // The relay's owner route still answers, with and without its token.
  const hosts = await s.call('GET', '/relay/v1/hosts', { authorization: 'Bearer owner-token-for-this-test' });
  assert.equal(hosts.status, 200);
  assert.deepEqual(JSON.parse(hosts.body), { hosts: [] });
  assert.notEqual((await s.call('GET', '/relay/v1/hosts')).status, 200);
  assert.equal((await s.call('GET', '/anything/else')).status, 404);
  // A host's socket is taken by the relay; an upgrade for another path is dropped.
  const ws = await s.call('GET', '/relay/v1/host', upgrade);
  assert.equal(ws.status, 101);
  await assert.rejects(s.call('GET', '/feyn/v1/blobs/key', upgrade));
});

test('without BLOB_DIR the relay runs as it did: no blob routes', async (t) => {
  const s = await start(t, () => ({}));
  assert.equal((await s.call('GET', '/feyn/v1/blobs/key')).status, 404);
  assert.equal((await s.call('GET', '/relay/v1/hosts', { authorization: 'Bearer owner-token-for-this-test' })).status, 200);
  assert.equal(existsSync(join(s.run, 'state', 'blob-key.json')), false);
});

test('the statement is served from the state directory, before the relay; its line is logged at start', async (t) => {
  const none = await start(t, () => ({}));
  assert.ok(none.out.join('').includes('statement: missing, machines will refuse this relay'), none.out.join(''));
  assert.equal((await none.call('GET', '/feyn/v1/relay')).status, 404);
  const s = await start(t, (run) => {
    writeFileSync(join(run, 'state', 'relay-statement.json'), '{"v":1,"relay":"relay.example.com","issued":"2026-10-22","expires":"2027-10-22"}');
    writeFileSync(join(run, 'state', 'relay-statement.json.sig'), 'sig');
    return {};
  });
  assert.ok(s.out.join('').includes('statement: relay.example.com until 2027-10-22'), s.out.join(''));
  const json = await s.call('GET', '/feyn/v1/relay');
  assert.deepEqual([json.status, JSON.parse(json.body).relay], [200, 'relay.example.com']);
  assert.equal((await s.call('GET', '/feyn/v1/relay.sig')).body, 'sig');
});

test('the join routes are served, and machines are kept beside the relay\'s state', async (t) => {
  const s = await start(t, () => ({}));
  const call = (method, path, body) => fetch(`http://127.0.0.1:${s.port}${path}`, { method, body: body && JSON.stringify(body) });
  const key = Buffer.alloc(32, 7).toString('base64url');
  const r = await call('POST', '/feyn/v1/join', { name: 'omarchy', key, details: {} });
  assert.equal(r.status, 201);
  const { id } = await r.json();
  assert.deepEqual(await (await call('GET', `/feyn/v1/join/${id}`)).json(), { state: 'waiting' });
  assert.ok(existsSync(join(s.run, 'state', 'machines.json')));
  assert.equal((await call('POST', `/feyn/v1/machines/${id}/enrolments`, { name: 'alice', at: Date.now(), sig: 'x' })).status, 403);
});
