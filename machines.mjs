// Machines joining the relay (relay distribution design, section 4). A
// machine asks to join with its own Ed25519 key; the operator approves it on
// the admin page by its code; an approved machine then asks for a byokit
// enrolment for each of its people, signing with that key, so the owner token
// is used by nobody.
//
//   POST   /feyn/v1/join                      {name, key, details}: a request and its code
//   GET    /feyn/v1/join/<id>                 {state}: waiting, approved, refused or expired
//   DELETE /feyn/v1/join/<id>                 signed (withdraw): the request withdrawn
//   POST   /feyn/v1/machines/<id>/enrolments  signed (enrol, the person): a byokit ticket
//   POST   /feyn/v1/machines/<id>/leave       signed (leave): its hosts revoked, the machine dropped
//
// A machine's id is the base64url of SHA-256 of its raw public key, cut to
// 22 characters; a request has the id of the machine that made it. A signed
// body is {at, sig, ...}: `sig` is Ed25519 over
// "feyn-relay\n<purpose>\n<machine id>\n<field>\n<at>", `at` within five
// minutes of the relay's clock.
//
// Kept in `machines.json` beside byokit's state: approved machines and the
// requests not yet answered for the last time. An old copy is never
// restored: it would bring back a machine that was removed.
import { createHash, createPublicKey, randomInt, verify } from 'node:crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';

export const LIMITS = {
  body: 4096, // a request's body, in bytes
  requestMs: 3600_000, // a request waits this long
  perAddress: 10, // join requests from one address in an hour
  addressMs: 3600_000,
  waiting: 50, // requests waiting at once
  skewMs: 300_000, // a signed body's `at` from the relay's clock
  ticketMs: 300_000, // a person's ticket
};
const CODE = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const NAME = /^[a-z0-9-]{1,63}$/;
// A person on a machine: the connector's own rule for a name.
const PERSON = /^[a-z_][a-z0-9_-]{0,31}$/;
const ID = /^[A-Za-z0-9_-]{22}$/;
const KEY = /^[A-Za-z0-9_-]{43}$/;
const SIG = /^[A-Za-z0-9_-]{86}$/;
const JOIN = '/feyn/v1/join';
const ONE = /^\/feyn\/v1\/join\/([^/]+)$/;
const MACHINE = /^\/feyn\/v1\/machines\/([^/]+)\/(enrolments|leave)$/;

export const machineId = (key) => createHash('sha256').update(Buffer.from(key, 'base64url')).digest('base64url').slice(0, 22);

// True when `sig` is the machine's signature of this purpose and field at `at`.
function signedBy(key, id, purpose, field, body, now) {
  const { at, sig } = body ?? {};
  if (!Number.isSafeInteger(at) || Math.abs(now - at) > LIMITS.skewMs || typeof sig !== 'string' || !SIG.test(sig)) return false;
  try {
    const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' });
    return verify(null, Buffer.from(`feyn-relay\n${purpose}\n${id}\n${field}\n${at}`, 'utf8'), publicKey, Buffer.from(sig, 'base64url'));
  } catch { return false; }
}

// A raw Ed25519 public key in base64url without padding, written only one way.
function goodKey(key) {
  if (typeof key !== 'string' || !KEY.test(key)) return false;
  const raw = Buffer.from(key, 'base64url');
  if (raw.length !== 32 || raw.toString('base64url') !== key) return false;
  try { createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' }); return true; } catch { return false; }
}

// `relay` is byokit's Relay, of which `enrolment`, `hosts` and `revoke` are
// used. `request(req, res)` answers true when the request was this module's.
export function createMachines({ file, relay, now = Date.now, trustProxy = false, log = () => {} }) {
  // {machines: [{id, name, key, details, from, joined, state: 'approved'}],
  //  requests: [{id, name, key, details, from, asked, code, state: 'waiting'|'refused'|'expired'}]}
  const state = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : { machines: [], requests: [] };
  if (!Array.isArray(state?.machines) || !Array.isArray(state?.requests)) throw new Error(`${file} does not hold machines`);
  // address -> times of its join requests in the last hour; in memory only.
  const asked = new Map();

  function save() {
    writeFileSync(`${file}.tmp`, JSON.stringify(state), { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
  }

  // A waiting request an hour old is expired; one answered for the last time
  // is gone already. Requests nobody asks about again go after a day.
  function sweep() {
    const t = now();
    let changed = false;
    for (const r of state.requests) {
      if (r.state === 'waiting' && t - r.asked >= LIMITS.requestMs) { r.state = 'expired'; changed = true; }
    }
    const kept = state.requests.filter((r) => r.state === 'waiting' || t - r.asked < 24 * 3600_000);
    if (kept.length !== state.requests.length) { state.requests = kept; changed = true; }
    if (changed) save();
  }

  const waiting = () => state.requests.filter((r) => r.state === 'waiting');
  const machine = (id) => state.machines.find((m) => m.id === id);

  function newCode() {
    const taken = new Set(waiting().map((r) => r.code));
    for (;;) {
      let c = '';
      for (let i = 0; i < 8; i++) c += CODE[randomInt(CODE.length)];
      if (!taken.has(c)) return c;
    }
  }

  function addressOf(req) {
    const forwarded = trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0].trim() : '';
    return forwarded || req.socket.remoteAddress || '';
  }

  // One more join request from this address; false past the hour's limit.
  function allow(address) {
    const t = now();
    const times = (asked.get(address) ?? []).filter((x) => t - x < LIMITS.addressMs);
    for (const [a, v] of asked) if (!v.some((x) => t - x < LIMITS.addressMs)) asked.delete(a);
    if (times.length >= LIMITS.perAddress) { asked.set(address, times); return false; }
    asked.set(address, [...times, t]);
    return true;
  }

  async function revokeHosts(id) {
    for (const h of relay.hosts()) if (h.meta?.machine === id) await relay.revoke(h.id);
  }

  // What the admin page uses.
  function requests() { sweep(); return waiting().map((r) => ({ ...r })); }
  function machines() { return state.machines.map((m) => ({ ...m })); }
  async function approve(id) {
    sweep();
    const r = waiting().find((x) => x.id === id);
    if (!r) throw new Error('no such request');
    state.requests = state.requests.filter((x) => x !== r);
    state.machines = [...state.machines.filter((m) => m.id !== id), { id, name: r.name, key: r.key, details: r.details, from: r.from, joined: now(), state: 'approved' }];
    save();
    log(`machines: ${r.name} ${id} approved`);
  }
  async function refuse(id) {
    sweep();
    const r = waiting().find((x) => x.id === id);
    if (!r) throw new Error('no such request');
    r.state = 'refused';
    save();
    log(`machines: ${r.name} ${id} refused`);
  }
  // Every byokit host the machine enrolled is revoked, then the machine goes.
  async function remove(id) {
    const m = machine(id);
    if (!m) throw new Error('no such machine');
    await revokeHosts(id);
    state.machines = state.machines.filter((x) => x.id !== id);
    save();
    log(`machines: ${m.name} ${id} removed`);
  }

  function json(res, status, body) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(body === undefined ? undefined : JSON.stringify(body));
  }
  // The body as an object, or undefined when it is not one or is too long.
  async function body(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > LIMITS.body) { req.resume(); return undefined; }
      chunks.push(c);
    }
    try {
      const o = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      return o && typeof o === 'object' && !Array.isArray(o) ? o : undefined;
    } catch { return undefined; }
  }

  async function join(req, res) {
    if (!allow(addressOf(req))) return json(res, 429, { error: 'too many requests' });
    const b = await body(req);
    const details = b?.details;
    if (!b || typeof b.name !== 'string' || !NAME.test(b.name) || !goodKey(b.key) || !details || typeof details !== 'object' || Array.isArray(details)) {
      return json(res, 400, { error: 'bad request' });
    }
    sweep();
    const id = machineId(b.key);
    if (machine(id)) return json(res, 200, { id, state: 'approved' });
    const w = waiting().find((r) => r.id === id);
    if (w) return json(res, 200, { id, code: w.code, again: true });
    if (waiting().length >= LIMITS.waiting) return json(res, 429, { error: 'too many waiting' });
    const r = { id, name: b.name, key: b.key, details, from: addressOf(req), asked: now(), code: newCode(), state: 'waiting' };
    state.requests = [...state.requests.filter((x) => x.id !== id), r];
    save();
    log(`machines: ${r.name} ${id} asks to join from ${r.from}`);
    return json(res, 201, { id, code: r.code, expires_in: LIMITS.requestMs / 1000 });
  }

  async function one(req, res, id) {
    sweep();
    if (req.method === 'GET') {
      if (machine(id)) return json(res, 200, { state: 'approved' });
      const r = state.requests.find((x) => x.id === id);
      if (!r) return json(res, 404, { error: 'not found' });
      // A refused or expired request is answered once more, then forgotten.
      if (r.state !== 'waiting') { state.requests = state.requests.filter((x) => x !== r); save(); }
      return json(res, 200, { state: r.state });
    }
    if (req.method === 'DELETE') {
      const b = await body(req);
      const r = state.requests.find((x) => x.id === id);
      if (!r) return json(res, 404, { error: 'not found' });
      if (!signedBy(r.key, id, 'withdraw', '', b, now())) return json(res, 403, { error: 'forbidden' });
      state.requests = state.requests.filter((x) => x !== r);
      save();
      log(`machines: ${r.name} ${id} withdrew its request`);
      return json(res, 204);
    }
    return json(res, 405, { error: 'method' });
  }

  async function signed(req, res, id, what) {
    if (req.method !== 'POST') return json(res, 405, { error: 'method' });
    const b = await body(req);
    if (!b) return json(res, 400, { error: 'bad request' });
    const m = machine(id);
    if (what === 'enrolments') {
      if (typeof b.name !== 'string' || !PERSON.test(b.name)) return json(res, 400, { error: 'bad request' });
      if (!m || !signedBy(m.key, id, 'enrol', b.name, b, now())) return json(res, 403, { error: 'forbidden' });
      const { token, expires } = await relay.enrolment({ name: `${m.name}/${b.name}`, ttlMs: LIMITS.ticketMs, meta: { machine: id, person: b.name } });
      log(`machines: ${m.name} ${id} enrols ${b.name}`);
      return json(res, 201, { ticket: token, expires });
    }
    if (!m) return json(res, 404, { error: 'not found' });
    if (!signedBy(m.key, id, 'leave', '', b, now())) return json(res, 403, { error: 'forbidden' });
    await revokeHosts(id);
    state.machines = state.machines.filter((x) => x.id !== id);
    save();
    log(`machines: ${m.name} ${id} left`);
    return json(res, 204);
  }

  async function request(req, res) {
    const path = new URL(req.url ?? '/', 'http://relay').pathname;
    if (path === JOIN) return req.method === 'POST' ? (await join(req, res), true) : (json(res, 405, { error: 'method' }), true);
    let m = ONE.exec(path);
    if (m) {
      if (!ID.test(m[1])) { json(res, 404, { error: 'not found' }); return true; }
      await one(req, res, m[1]);
      return true;
    }
    m = MACHINE.exec(path);
    if (m) {
      if (!ID.test(m[1])) { json(res, 404, { error: 'not found' }); return true; }
      await signed(req, res, m[1], m[2]);
      return true;
    }
    return false;
  }

  return { request, requests, machines, approve, refuse, remove };
}
