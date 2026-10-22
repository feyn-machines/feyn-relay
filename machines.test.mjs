// Machines joining the relay (relay distribution design, section 4), on
// loopback with a fake clock and a fake byokit: a join request and its code,
// the operator's answer, a person's ticket asked for with the machine's key,
// and a machine leaving.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createMachines, LIMITS } from './machines.mjs';

// A machine as Interfaces describe one, computed here without the module's code.
function makeMachine(name = 'omarchy') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = publicKey.export({ format: 'jwk' }).x;
  const id = createHash('sha256').update(Buffer.from(key, 'base64url')).digest('base64url').slice(0, 22);
  const signed = (purpose, field, at) => ({ at, sig: sign(null, Buffer.from(`feyn-relay\n${purpose}\n${id}\n${field}\n${at}`, 'utf8'), privateKey).toString('base64url') });
  return { name, key, id, signed, body: { name, key, details: { os: 'Arch Linux', cpu: 'x' } } };
}

// byokit's three calls this module uses, kept in memory.
function fakeByokit() {
  const hosts = [];
  const enrolments = [];
  let n = 0;
  return {
    hosts: () => hosts.map((h) => ({ ...h, online: true, devices: 1 })),
    enrolment: async (o) => { enrolments.push(o); return { token: `ticket.${++n}`, expires: 1_000 + n }; },
    revoke: async (id) => { const i = hosts.findIndex((h) => h.id === id); if (i < 0) return false; hosts.splice(i, 1); return true; },
    // What a host claiming a ticket would add.
    add: (id, meta) => hosts.push({ id, key: 'k', name: id, added: 0, ...(meta ? { meta } : {}) }),
    enrolments,
  };
}

async function setup(t, o = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'feyn-machines-'));
  const clock = { ms: Date.parse('2026-10-22T09:00:00Z') };
  const byokit = fakeByokit();
  const file = join(dir, 'machines.json');
  const make = () => createMachines({ file, relay: byokit, now: () => clock.ms, trustProxy: o.trustProxy ?? true });
  const machines = make();
  const server = createServer((req, res) => {
    void machines.request(req, res).then((done) => { if (!done) res.writeHead(404).end('not ours'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, body, { from = '203.0.113.7', raw } = {}) => {
    const r = await fetch(base + path, {
      method,
      // A forged first value, then the address the proxy saw.
      headers: { 'content-type': 'application/json', 'x-forwarded-for': `6.6.6.6, ${from}` },
      ...(body !== undefined || raw !== undefined ? { body: raw ?? JSON.stringify(body) } : {}),
    });
    const text = await r.text();
    return { status: r.status, text, json: text ? JSON.parse(text) : undefined };
  };
  const join_ = (m, opts) => call('POST', '/feyn/v1/join', m.body, opts);
  const state = (id) => call('GET', `/feyn/v1/join/${id}`);
  const enrol = (m, person, at = clock.ms, signer = m) => call('POST', `/feyn/v1/machines/${m.id}/enrolments`, { name: person, ...signer.signed('enrol', person, at) });
  return { dir, file, base, clock, byokit, machines, make, call, join: join_, state, enrol, tick: (ms) => { clock.ms += ms; } };
}

test('a new request: an id, a code of eight characters, an hour', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  const r = await s.join(m);
  assert.equal(r.status, 201);
  assert.equal(r.json.id, m.id);
  assert.match(r.json.code, /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$/);
  assert.equal(r.json.expires_in, 3600);
  assert.deepEqual((await s.state(m.id)).json, { state: 'waiting' });
  // The operator sees it, with where it came from.
  const [w] = s.machines.requests();
  assert.deepEqual([w.id, w.name, w.code, w.from, w.details.os], [m.id, 'omarchy', r.json.code, '203.0.113.7', 'Arch Linux']);
  // Kept on disk, 0600, never with a private key.
  assert.equal(statSync(s.file).mode & 0o777, 0o600);
  const kept = JSON.parse(readFileSync(s.file, 'utf8'));
  assert.equal(kept.requests[0].key, m.key);
  assert.deepEqual(kept.machines, []);
});

test('the same key again while it waits: the same id and code, again', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  const first = await s.join(m);
  s.tick(60_000);
  const again = await s.join(m);
  assert.equal(again.status, 200);
  assert.deepEqual(again.json, { id: m.id, code: first.json.code, again: true });
  assert.equal(s.machines.requests().length, 1);
});

test('codes are different for different machines', async (t) => {
  const s = await setup(t);
  const codes = new Set();
  for (let i = 0; i < 10; i++) codes.add((await s.join(makeMachine(`m${i}`), { from: `198.51.100.${i}` })).json.code);
  assert.equal(codes.size, 10);
});

test('approved: the request answers approved, a join again says so, the machine is kept', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  await s.join(m);
  s.tick(5_000);
  await s.machines.approve(m.id);
  assert.deepEqual((await s.state(m.id)).json, { state: 'approved' });
  assert.deepEqual((await s.state(m.id)).json, { state: 'approved' });
  assert.deepEqual(s.machines.requests(), []);
  const [mm] = s.machines.machines();
  assert.deepEqual([mm.id, mm.name, mm.key, mm.state, mm.joined, mm.from], [m.id, 'omarchy', m.key, 'approved', s.clock.ms, '203.0.113.7']);
  const again = await s.join(m);
  assert.deepEqual([again.status, again.json], [200, { id: m.id, state: 'approved' }]);
  // Kept across a restart.
  assert.deepEqual(s.make().machines().map((x) => x.id), [m.id]);
});

test('refused: answered once more, then forgotten', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  await s.join(m);
  await s.machines.refuse(m.id);
  assert.deepEqual(s.machines.requests(), []);
  assert.deepEqual((await s.state(m.id)).json, { state: 'refused' });
  assert.equal((await s.state(m.id)).status, 404);
  // It may ask again; that is a new request.
  assert.equal((await s.join(m)).status, 201);
});

test('expired after an hour: answered once more, then forgotten; its code is free again', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  await s.join(m);
  s.tick(3600_000 - 1);
  assert.deepEqual((await s.state(m.id)).json, { state: 'waiting' });
  s.tick(1);
  assert.deepEqual(s.machines.requests(), []);
  assert.deepEqual((await s.state(m.id)).json, { state: 'expired' });
  assert.equal((await s.state(m.id)).status, 404);
  await assert.rejects(s.machines.approve(m.id));
});

test('withdrawn with the machine\'s signature; another key or an old time cannot', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  const other = makeMachine('other');
  await s.join(m);
  const by = (signer, at = s.clock.ms) => s.call('DELETE', `/feyn/v1/join/${m.id}`, signer === m ? m.signed('withdraw', '', at) : { ...signer.signed('withdraw', '', at) });
  assert.equal((await by(other)).status, 403);
  assert.equal((await by(m, s.clock.ms - LIMITS.skewMs - 1)).status, 403);
  assert.equal((await by(m, s.clock.ms + LIMITS.skewMs + 1)).status, 403);
  assert.equal((await s.call('DELETE', `/feyn/v1/join/${m.id}`, { at: s.clock.ms })).status, 403);
  assert.equal((await by(m)).status, 204);
  assert.equal((await s.state(m.id)).status, 404);
  assert.deepEqual(s.machines.requests(), []);
  assert.equal((await by(m)).status, 404);
});

test('a bad body is 400', async (t) => {
  const s = await setup(t);
  const m = makeMachine();
  const bad = [
    { ...m.body, name: 'Omarchy' }, { ...m.body, name: '' }, { ...m.body, name: 'a'.repeat(64) }, { ...m.body, name: 'a_b' },
    { ...m.body, key: m.key.slice(1) }, { ...m.body, key: `${m.key}=` }, { ...m.body, key: 7 },
    { ...m.body, details: 'x' }, { ...m.body, details: [1] }, { name: m.name, key: m.key },
  ];
  // Each from an address of its own: a bad request counts toward the address's limit too.
  let n = 0;
  const post = (b, raw) => s.call('POST', '/feyn/v1/join', b, { raw, from: `198.51.100.${n++}` });
  for (const b of bad) assert.equal((await post(b)).status, 400, JSON.stringify(b));
  assert.equal((await post(undefined, 'not json')).status, 400);
  assert.equal((await post({ ...m.body, details: { x: 'y'.repeat(4096) } })).status, 400);
  assert.equal((await post({ ...m.body, name: 'a'.repeat(63) })).status, 201);
  assert.equal((await s.call('GET', '/feyn/v1/join/not-an-id')).status, 404);
  assert.equal((await s.call('PUT', '/feyn/v1/join')).status, 405);
});

test('429: more than ten requests from one address in an hour', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < LIMITS.perAddress; i++) assert.equal((await s.join(makeMachine(), { from: '192.0.2.1' })).status, 201);
  assert.equal((await s.join(makeMachine(), { from: '192.0.2.1' })).status, 429);
  // Another address is not held back by it.
  assert.equal((await s.join(makeMachine(), { from: '192.0.2.2' })).status, 201);
  s.tick(3600_000);
  assert.equal((await s.join(makeMachine(), { from: '192.0.2.1' })).status, 201);
});

test('a forged first X-Forwarded-For value does not escape the limit; cf-connecting-ip is taken first', async (t) => {
  const s = await setup(t);
  const post = (headers) => fetch(`${s.base}/feyn/v1/join`, { method: 'POST', headers, body: JSON.stringify(makeMachine().body) });
  for (let i = 0; i < LIMITS.perAddress; i++) assert.equal((await post({ 'x-forwarded-for': `10.9.0.${i}, 192.0.2.50` })).status, 201);
  assert.equal((await post({ 'x-forwarded-for': '10.9.1.1, 192.0.2.50' })).status, 429);
  assert.equal((await post({ 'cf-connecting-ip': '192.0.2.51', 'x-forwarded-for': '192.0.2.50' })).status, 201);
  assert.ok(s.machines.requests().some((r) => r.from === '192.0.2.51'));
});

test('the address is the socket\'s unless TRUST_PROXY: a forwarded address is ignored', async (t) => {
  const s = await setup(t, { trustProxy: false });
  for (let i = 0; i < LIMITS.perAddress; i++) assert.equal((await s.join(makeMachine(), { from: `192.0.2.${i}` })).status, 201);
  assert.equal((await s.join(makeMachine(), { from: '192.0.2.99' })).status, 429);
  assert.match(s.machines.requests()[0].from, /127\.0\.0\.1/);
});

test('429: more than fifty waiting in all; a request that waits may still ask again', async (t) => {
  const s = await setup(t);
  const first = makeMachine();
  await s.join(first, { from: '10.1.0.0' });
  for (let i = 1; i < LIMITS.waiting; i++) assert.equal((await s.join(makeMachine(), { from: `10.1.${i}.0` })).status, 201);
  assert.equal((await s.join(makeMachine(), { from: '10.2.0.0' })).status, 429);
  assert.equal((await s.join(first, { from: '10.3.0.0' })).status, 200);
  await s.machines.refuse(first.id);
  assert.equal((await s.join(makeMachine(), { from: '10.4.0.0' })).status, 201);
});

async function approved(s, name = 'omarchy') {
  const m = makeMachine(name);
  await s.join(m, { from: `192.0.2.${name.length}` });
  await s.machines.approve(m.id);
  return m;
}

test('an approved machine is given a ticket for a person, named and marked as its own', async (t) => {
  const s = await setup(t);
  const m = await approved(s);
  const r = await s.enrol(m, 'alice');
  assert.deepEqual([r.status, r.json], [201, { ticket: 'ticket.1', expires: 1_001 }]);
  assert.deepEqual(s.byokit.enrolments, [{ name: 'omarchy/alice', ttlMs: 300_000, meta: { machine: m.id, person: 'alice' } }]);
  assert.equal((await s.enrol(m, 'bob')).status, 201);
  assert.equal(s.byokit.enrolments.length, 2);
});

test('enrol refused: replayed after five minutes, signed by another key, for another name, not approved, a bad name', async (t) => {
  const s = await setup(t);
  const m = await approved(s);
  const other = await approved(s, 'other');
  const at = s.clock.ms;
  s.tick(LIMITS.skewMs + 1);
  assert.equal((await s.enrol(m, 'alice', at)).status, 403);
  assert.equal((await s.enrol(m, 'alice', s.clock.ms, other)).status, 403);
  // The signature names the person: it does not hold for another.
  const forAlice = m.signed('enrol', 'alice', s.clock.ms);
  assert.equal((await s.call('POST', `/feyn/v1/machines/${m.id}/enrolments`, { name: 'bob', ...forAlice })).status, 403);
  // Waiting is not approved.
  const waiting = makeMachine('waiting');
  await s.join(waiting);
  assert.equal((await s.enrol(waiting, 'alice')).status, 403);
  assert.equal((await s.enrol(makeMachine('unknown'), 'alice')).status, 403);
  assert.equal((await s.enrol(m, 'Alice')).status, 400);
  assert.deepEqual(s.byokit.enrolments, []);
});

test('leave: only that machine\'s hosts are revoked, and the machine is dropped', async (t) => {
  const s = await setup(t);
  const m = await approved(s);
  const other = await approved(s, 'other');
  s.byokit.add('h1', { machine: m.id, person: 'alice' });
  s.byokit.add('h2', { machine: m.id, person: 'bob' });
  s.byokit.add('h3', { machine: other.id, person: 'carol' });
  s.byokit.add('h4');
  const leave = (signer, at = s.clock.ms) => s.call('POST', `/feyn/v1/machines/${m.id}/leave`, signer.signed('leave', '', at));
  assert.equal((await leave(other)).status, 403);
  assert.equal((await leave(m, s.clock.ms - LIMITS.skewMs - 1)).status, 403);
  assert.equal(s.byokit.hosts().length, 4);
  assert.equal((await leave(m)).status, 204);
  assert.deepEqual(s.byokit.hosts().map((h) => h.id), ['h3', 'h4']);
  assert.deepEqual(s.machines.machines().map((x) => x.id), [other.id]);
  assert.equal((await s.enrol(m, 'alice')).status, 403);
  assert.equal((await leave(m)).status, 404);
});

test('remove on the admin page: like leave, for the operator', async (t) => {
  const s = await setup(t);
  const m = await approved(s);
  const other = await approved(s, 'other');
  s.byokit.add('h1', { machine: m.id, person: 'alice' });
  s.byokit.add('h3', { machine: other.id, person: 'carol' });
  await s.machines.remove(m.id);
  assert.deepEqual(s.byokit.hosts().map((h) => h.id), ['h3']);
  assert.deepEqual(s.machines.machines().map((x) => x.id), [other.id]);
  // It may ask again, and the operator decides again.
  assert.equal((await s.join(m)).status, 201);
});

test('with byokit itself: a ticket enrols a host marked with its machine, and leave revokes it', async (t) => {
  const { Relay, RelayClient } = await import('@byokit/relay');
  const { Host, keyPair } = await import('@byokit/link');
  const dir = mkdtempSync(join(tmpdir(), 'feyn-machines-'));
  let saved;
  const relay = await Relay.open({ store: { load: () => saved, save: (x) => { saved = structuredClone(x); } } });
  const machines = createMachines({ file: join(dir, 'machines.json'), relay });
  const server = createServer((req, res) => { void machines.request(req, res).then((done) => { if (!done) res.writeHead(404).end(); }); });
  server.on('upgrade', (req, socket, head) => { if (!relay.upgrade(req, socket, head)) socket.destroy(); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const host = await Host.open({ keys: keyPair(), name: 'alice', confirm: () => true, handle: () => ({}) });
  let client;
  t.after(async () => { client?.stop(); host.close(); relay.close(); server.closeAllConnections(); await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }); });
  const post = (path, body) => fetch(base + path, { method: 'POST', body: JSON.stringify(body) });

  const m = makeMachine();
  assert.equal((await post('/feyn/v1/join', m.body)).status, 201);
  await machines.approve(m.id);
  const r = await post(`/feyn/v1/machines/${m.id}/enrolments`, { name: 'alice', ...m.signed('enrol', 'alice', Date.now()) });
  const { ticket } = await r.json();
  client = new RelayClient(host, { url: `${base.replace('http', 'ws')}/relay/v1/host`, enrol: ticket });
  for (let i = 0; i < 400 && client.status !== 'online'; i++) await new Promise((x) => setTimeout(x, 10));
  assert.deepEqual(relay.hosts().map((h) => [h.name, h.meta]), [['omarchy/alice', { machine: m.id, person: 'alice' }]]);
  assert.equal((await post(`/feyn/v1/machines/${m.id}/leave`, m.signed('leave', '', Date.now()))).status, 204);
  assert.deepEqual(relay.hosts(), []);
});
