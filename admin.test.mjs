// The admin page (relay distribution design, section 5), on loopback with a
// fake clock, fake machines and a fake byokit: the first account from the
// environment, signing in, the lock, the Origin check, the reset link, and
// what the page shows and does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAdmin, LIMITS, resetPassword } from './admin.mjs';

const HOST = 'relay.example.com';
const ORIGIN = `https://${HOST}`;
const PASSWORD = 'correct horse battery';

function fakes() {
  const requests = [{ id: 'reqAAAAAAAAAAAAAAAAAAA', name: 'omarchy', code: 'ABCD2345', details: { os: '<script>alert(1)</script>' }, from: '203.0.113.7', asked: 0 }];
  const machines = [{ id: 'macBBBBBBBBBBBBBBBBBBB', name: 'studio', key: 'k', details: {}, from: '203.0.113.8', joined: 0, state: 'approved' }];
  const hosts = [
    { id: 'h1', name: 'studio/alice', meta: { machine: 'macBBBBBBBBBBBBBBBBBBB', person: 'alice' }, online: true, devices: 2 },
    { id: 'h2', name: 'by hand', online: false, devices: 0 },
  ];
  const done = [];
  return {
    done,
    machines: {
      requests: () => requests,
      machines: () => machines,
      approve: async (id) => { done.push(['approve', id]); },
      refuse: async (id) => { done.push(['refuse', id]); },
      remove: async (id) => { done.push(['remove', id]); },
    },
    relay: { hosts: () => hosts, revoke: async (id) => { done.push(['revoke', id]); return true; } },
  };
}

async function setup(t, { env = { ADMIN_USER: 'owner', ADMIN_PASSWORD: PASSWORD }, dir } = {}) {
  dir ??= mkdtempSync(join(tmpdir(), 'feyn-admin-'));
  const clock = { ms: Date.parse('2026-10-22T09:00:00Z') };
  const f = fakes();
  const lines = [];
  const file = join(dir, 'admin.json');
  const admin = await createAdmin({ file, env: { RELAY_HOST: HOST, ...env }, machines: f.machines, relay: f.relay, now: () => clock.ms, log: (l) => lines.push(l), trustProxy: true });
  const server = createServer((req, res) => { void admin.request(req, res).then((done) => { if (!done) res.writeHead(404).end('not ours'); }); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (method, path, { form, cookie, origin = ORIGIN, from } = {}) => {
    const headers = {};
    if (from) headers['cf-connecting-ip'] = from;
    if (form) headers['content-type'] = 'application/x-www-form-urlencoded';
    if (cookie) headers.cookie = cookie;
    if (origin) headers.origin = origin;
    const r = await fetch(base + path, { method, headers, redirect: 'manual', ...(form ? { body: new URLSearchParams(form).toString() } : {}) });
    return { status: r.status, cookie: r.headers.get('set-cookie'), location: r.headers.get('location'), csp: r.headers.get('content-security-policy'), referrer: r.headers.get('referrer-policy'), text: await r.text() };
  };
  const signIn = (user = 'owner', password = PASSWORD, from) => call('POST', '/admin/sign-in', { form: { user, password }, from });
  const session = async (password = PASSWORD) => {
    const r = await signIn('owner', password);
    assert.equal(r.status, 303, r.text);
    return r.cookie.split(';')[0];
  };
  return { dir, file, clock, lines, f, call, signIn, session, tick: (ms) => { clock.ms += ms; } };
}

test('no admin.json: the account is made from the environment, once', async (t) => {
  const s = await setup(t);
  assert.deepEqual(s.lines, ['admin: account owner set up']);
  assert.equal(statSync(s.file).mode & 0o777, 0o600);
  const kept = readFileSync(s.file, 'utf8');
  assert.ok(!kept.includes(PASSWORD), 'the password is not kept');
  assert.equal(JSON.parse(kept).user, 'owner');
  assert.equal((await s.signIn()).status, 303);
});

test('no admin.json and no password, a short one, or no name: start refused with a clear message', async () => {
  for (const env of [{ ADMIN_USER: 'owner' }, { ADMIN_USER: 'owner', ADMIN_PASSWORD: 'x'.repeat(11) }, { ADMIN_PASSWORD: PASSWORD }]) {
    const dir = mkdtempSync(join(tmpdir(), 'feyn-admin-'));
    await assert.rejects(createAdmin({ file: join(dir, 'admin.json'), env: { RELAY_HOST: HOST, ...env }, machines: fakes().machines, relay: fakes().relay }), /ADMIN_USER and ADMIN_PASSWORD \(at least 12 characters\)/);
    assert.equal(existsSync(join(dir, 'admin.json')), false);
    rmSync(dir, { recursive: true, force: true });
  }
  await assert.rejects(createAdmin({ file: join(tmpdir(), 'none', 'admin.json'), env: { ADMIN_USER: 'owner', ADMIN_PASSWORD: PASSWORD }, machines: fakes().machines, relay: fakes().relay }), /RELAY_HOST/);
});

test('admin.json present: the environment is not read again (Review Focus 4)', async (t) => {
  const first = await setup(t);
  // The same state directory, started again with another password in .env, or none.
  const again = await setup(t, { dir: first.dir, env: { ADMIN_USER: 'other', ADMIN_PASSWORD: 'a new password here' } });
  assert.deepEqual(again.lines, []);
  assert.equal((await again.signIn('owner', PASSWORD)).status, 303);
  assert.equal((await again.signIn('other', 'a new password here')).status, 403);
  assert.equal((await again.signIn('owner', 'a new password here')).status, 403);
  const none = await setup(t, { dir: first.dir, env: {} });
  assert.equal((await none.signIn()).status, 303);
});

test('signing in sets a session cookie for /admin, twelve hours; signing out ends it', async (t) => {
  const s = await setup(t);
  const r = await s.signIn();
  assert.equal(r.location, '/admin');
  const parts = r.cookie.split(';').map((x) => x.trim());
  assert.match(parts[0], /^feyn_admin=[A-Za-z0-9_-]{43}$/);
  for (const a of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/admin', `Max-Age=${12 * 3600}`]) assert.ok(parts.includes(a), `${a} in ${r.cookie}`);
  const cookie = parts[0];
  assert.match((await s.call('GET', '/admin', { cookie })).text, /Requests/);
  s.tick(LIMITS.sessionMs - 1);
  assert.match((await s.call('GET', '/admin', { cookie })).text, /Requests/);
  s.tick(1);
  assert.match((await s.call('GET', '/admin', { cookie })).text, /Sign in/);
  const c2 = await s.session();
  assert.equal((await s.call('POST', '/admin/sign-out', { cookie: c2, form: {} })).status, 303);
  assert.match((await s.call('GET', '/admin', { cookie: c2 })).text, /Sign in/);
  assert.equal((await s.signIn('owner', 'wrong password!')).status, 403);
  assert.equal((await s.signIn('someone', PASSWORD)).status, 403);
});

test('ten wrong passwords in fifteen minutes lock sign-in for fifteen minutes', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < LIMITS.failures - 1; i++) { assert.equal((await s.signIn('owner', `wrong ${i}`)).status, 403); s.tick(60_000); }
  assert.equal((await s.signIn()).status, 303);
  assert.equal((await s.signIn('owner', 'wrong 9')).status, 403);
  // Locked: even the right password is refused.
  const locked = await s.signIn();
  assert.equal(locked.status, 429);
  assert.match(locked.text, /locked/);
  s.tick(LIMITS.lockMs - 1);
  assert.equal((await s.signIn()).status, 429);
  s.tick(1);
  assert.equal((await s.signIn()).status, 303);
});

test('wrong passwords spread over more than fifteen minutes do not lock', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < 20; i++) { assert.equal((await s.signIn('owner', `wrong ${i}`)).status, 403); s.tick(LIMITS.failureWindowMs / 9); }
  assert.equal((await s.signIn()).status, 303);
});

test('every POST without the cookie, or with another Origin, is 403', async (t) => {
  const s = await setup(t);
  const cookie = await s.session();
  const posts = [['/admin/approve', { id: 'reqAAAAAAAAAAAAAAAAAAA' }], ['/admin/refuse', { id: 'reqAAAAAAAAAAAAAAAAAAA' }], ['/admin/remove-machine', { id: 'macBBBBBBBBBBBBBBBBBBB' }], ['/admin/remove-host', { id: 'h2' }], ['/admin/password', { current: PASSWORD, password: 'a new password 1', again: 'a new password 1' }], ['/admin/sign-out', {}]];
  for (const [path, form] of posts) {
    assert.equal((await s.call('POST', path, { form })).status, 403, `${path} without the cookie`);
    assert.equal((await s.call('POST', path, { form, cookie: 'feyn_admin=forged' })).status, 403, `${path} with a forged cookie`);
    assert.equal((await s.call('POST', path, { form, cookie, origin: 'https://evil.example.com' })).status, 403, `${path} from another origin`);
    assert.equal((await s.call('POST', path, { form, cookie, origin: '' })).status, 403, `${path} with no origin`);
  }
  assert.deepEqual(s.f.done, []);
  // Sign-in and reset have no cookie yet, and still need the relay's own Origin.
  assert.equal((await s.call('POST', '/admin/sign-in', { form: { user: 'owner', password: PASSWORD }, origin: 'https://evil.example.com' })).status, 403);
  assert.equal((await s.call('POST', '/admin/reset', { form: { token: 'x', password: 'whatever whatever' }, origin: 'null' })).status, 403);
});

test('the page: requests, machines with their people, other hosts; every answer reaches its place', async (t) => {
  const s = await setup(t);
  const cookie = await s.session();
  const page = await s.call('GET', '/admin', { cookie });
  assert.equal(page.status, 200);
  assert.match(page.csp, /default-src 'none'/);
  for (const w of ['Requests', 'omarchy', 'ABCD-2345', '203.0.113.7', 'Machines', 'studio', 'alice (online, 2 devices)', 'Other hosts', 'by hand', 'Account']) assert.ok(page.text.includes(w), w);
  // What a machine sent is shown as text, never as markup.
  assert.ok(!page.text.includes('<script>alert(1)'));
  assert.ok(page.text.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert.ok(!page.text.includes('<script'), 'no script on the page');
  for (const [path, id, what] of [['/admin/approve', 'reqAAAAAAAAAAAAAAAAAAA', 'approve'], ['/admin/refuse', 'reqAAAAAAAAAAAAAAAAAAA', 'refuse'], ['/admin/remove-machine', 'macBBBBBBBBBBBBBBBBBBB', 'remove'], ['/admin/remove-host', 'h2', 'revoke']]) {
    const r = await s.call('POST', path, { form: { id }, cookie });
    assert.deepEqual([r.status, r.location], [303, '/admin']);
    assert.deepEqual(s.f.done.at(-1), [what, id]);
  }
  // A host that belongs to a machine is removed with its machine, not alone.
  assert.equal((await s.call('POST', '/admin/remove-host', { form: { id: 'h1' }, cookie })).status, 400);
  assert.equal((await s.call('GET', '/admin/elsewhere', { cookie })).status, 404);
  assert.equal((await s.call('GET', '/feyn/v1/relay')).text, 'not ours');
});

test('changing the password needs the current one; the new one is then the only one', async (t) => {
  const s = await setup(t);
  const cookie = await s.session();
  const change = (form) => s.call('POST', '/admin/password', { form, cookie });
  assert.equal((await change({ current: 'wrong password!', password: 'a new password 1', again: 'a new password 1' })).status, 403);
  assert.equal((await change({ current: PASSWORD, password: 'short', again: 'short' })).status, 400);
  assert.equal((await change({ current: PASSWORD, password: 'a new password 1', again: 'a new password 2' })).status, 400);
  assert.equal((await change({ current: PASSWORD, password: 'a new password 1', again: 'a new password 1' })).status, 303);
  assert.equal((await s.signIn('owner', PASSWORD)).status, 403);
  assert.equal((await s.signIn('owner', 'a new password 1')).status, 303);
});

test('reset-password: a link valid fifteen minutes, used once, for a new password and name', async (t) => {
  const s = await setup(t);
  const cookie = await s.session();
  const link = resetPassword({ file: s.file, host: HOST, now: () => s.clock.ms });
  const m = /^https:\/\/relay\.example\.com\/admin\/reset#([A-Za-z0-9_-]{43})$/.exec(link);
  assert.ok(m, link);
  const token = m[1];
  assert.ok(!readFileSync(s.file, 'utf8').includes(token), 'only a hash of the token is kept');
  // The page reads the token from the fragment, which never reaches the server.
  const page = await s.call('GET', '/admin/reset');
  assert.equal(page.status, 200);
  assert.match(page.text, /location\.hash/);
  assert.match(page.csp, /script-src 'sha256-/);
  const reset = (form) => s.call('POST', '/admin/reset', { form });
  assert.equal((await reset({ token: 'A'.repeat(43), user: '', password: 'a reset password', again: 'a reset password' })).status, 403);
  assert.equal((await reset({ token, user: '', password: 'short', again: 'short' })).status, 400);
  assert.equal((await reset({ token, user: 'owner2', password: 'a reset password', again: 'a reset password' })).status, 303);
  assert.equal((await reset({ token, user: '', password: 'another password', again: 'another password' })).status, 403);
  assert.equal((await s.signIn('owner2', 'a reset password')).status, 303);
  assert.equal((await s.signIn('owner', PASSWORD)).status, 403);
  // Sessions from before the reset are over.
  assert.match((await s.call('GET', '/admin', { cookie })).text, /Sign in/);
  // A link older than fifteen minutes does nothing.
  const late = /#(.+)$/.exec(resetPassword({ file: s.file, host: HOST, now: () => s.clock.ms }))[1];
  s.tick(LIMITS.resetMs + 1);
  assert.equal((await reset({ token: late, user: '', password: 'too late password', again: 'too late password' })).status, 403);
  assert.equal((await s.signIn('owner2', 'a reset password')).status, 303);
});

test('node admin.mjs reset-password prints the link for RELAY_HOST, from the state directory', async (t) => {
  const s = await setup(t);
  const run = spawnSync(process.execPath, [join(import.meta.dirname, 'admin.mjs'), 'reset-password'], { env: { PATH: process.env.PATH, RELAY_STATE: join(s.dir, 'relay.json'), RELAY_HOST: HOST }, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr);
  const token = /^https:\/\/relay\.example\.com\/admin\/reset#([A-Za-z0-9_-]{43})$/m.exec(run.stdout)?.[1];
  assert.ok(token, run.stdout);
  // The running relay reads the file again: the link works without a restart.
  assert.equal((await s.call('POST', '/admin/reset', { form: { token, user: '', password: 'from the command', again: 'from the command' } })).status, 303);
  assert.equal((await s.signIn('owner', 'from the command')).status, 303);
  // With no account yet there is nothing to reset.
  const empty = mkdtempSync(join(tmpdir(), 'feyn-admin-'));
  t.after(() => rmSync(empty, { recursive: true, force: true }));
  const none = spawnSync(process.execPath, [join(import.meta.dirname, 'admin.mjs'), 'reset-password'], { env: { PATH: process.env.PATH, RELAY_STATE: join(empty, 'relay.json'), RELAY_HOST: HOST }, encoding: 'utf8' });
  assert.notEqual(none.status, 0);
  assert.match(none.stderr, /no admin account/);
});

test('pages let the browser send the relay\'s own Origin on their forms; Origin: null stays refused', async (t) => {
  const s = await setup(t);
  const cookie = await s.session();
  // With no-referrer a browser sends Origin: null on a form's POST, and every form would be refused.
  for (const r of [await s.call('GET', '/admin'), await s.call('GET', '/admin', { cookie }), await s.call('GET', '/admin/reset'), await s.signIn('owner', 'wrong password!')]) {
    assert.equal(r.referrer, 'same-origin');
  }
  assert.equal((await s.call('POST', '/admin/approve', { form: { id: 'reqAAAAAAAAAAAAAAAAAAA' }, cookie, origin: 'null' })).status, 403);
  assert.equal((await s.call('POST', '/admin/sign-in', { form: { user: 'owner', password: PASSWORD }, origin: 'null' })).status, 403);
  assert.deepEqual(s.f.done, []);
});

test('one sign-in at a time: concurrent attempts are refused, not hashed past the lock', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < LIMITS.failures - 1; i++) assert.equal((await s.signIn('owner', `wrong ${i}`)).status, 403);
  // A burst of wrong ones at once: only one is hashed, and it is the tenth, which locks.
  const burst = await Promise.all(Array.from({ length: 6 }, (_, i) => s.signIn('owner', `burst ${i}`)));
  assert.deepEqual(burst.map((r) => r.status).sort(), [403, 429, 429, 429, 429, 429]);
  assert.equal((await s.signIn()).status, 429);
});

test('the lock is per address: another address still signs in', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < LIMITS.failures; i++) assert.equal((await s.signIn('owner', `wrong ${i}`, '198.51.100.66')).status, 403);
  assert.equal((await s.signIn('owner', PASSWORD, '198.51.100.66')).status, 429);
  assert.equal((await s.signIn('owner', PASSWORD, '203.0.113.5')).status, 303);
});

test('a ceiling for all addresses together: past it sign-in is locked for everyone', async (t) => {
  const s = await setup(t);
  for (let i = 0; i < LIMITS.globalFailures; i++) assert.equal((await s.signIn('owner', `wrong ${i}`, `10.7.${Math.floor(i / 4)}.${i % 4}`)).status, 403);
  assert.equal((await s.signIn('owner', PASSWORD, '203.0.113.5')).status, 429);
  s.tick(LIMITS.lockMs);
  assert.equal((await s.signIn('owner', PASSWORD, '203.0.113.5')).status, 303);
});
