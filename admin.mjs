// The relay's admin page (relay distribution design, section 5): one
// account, the machines' requests to approve or refuse, the machines and
// their people to remove. Server-rendered HTML; the only script is the one
// line of the reset page that reads the token from the address's fragment.
//
//   GET  /admin                        sign-in form, or the page
//   POST /admin/sign-in                {user, password}: a session cookie, 12 hours
//   POST /admin/sign-out
//   POST /admin/approve|refuse         {id} of a request
//   POST /admin/remove-machine         {id}: its hosts revoked, the machine dropped
//   POST /admin/remove-host            {id} of a byokit host that is no machine's
//   POST /admin/password               {current, password, again}
//   GET  /admin/reset                  the reset form; the token is after `#`
//   POST /admin/reset                  {token, user, password, again}: once, 15 minutes
//
// The account is made at first start from ADMIN_USER and ADMIN_PASSWORD and
// kept in `admin.json` (scrypt, mode 0600) beside the relay's state; once that
// file exists the two variables are not read again. Every POST must come from
// the relay's own origin (https://RELAY_HOST), and every one but sign-in and
// reset with a session cookie. Sessions are kept in memory: a restart signs
// the operator out.
//
//   node admin.mjs reset-password      on the relay's server: prints a one-time link
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { clientAddress } from './address.mjs';

const scrypt = promisify(scryptCb);

export const LIMITS = {
  password: 12, // characters, at least
  sessionMs: 12 * 3600_000,
  failures: 10, // wrong sign-ins from one address within the window lock it out
  globalFailures: 100, // wrong sign-ins from all addresses within the window lock sign-in for all
  failureWindowMs: 15 * 60_000,
  lockMs: 15 * 60_000,
  resetMs: 15 * 60_000,
  body: 4096,
};
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const COOKIE = 'feyn_admin';
const TOKEN = /^[A-Za-z0-9_-]{43}$/;
const USER = /^[A-Za-z0-9._@-]{1,64}$/;

const sha = (s) => createHash('sha256').update(s).digest('hex');
const sameHex = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const when = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';

function readAccount(file) {
  if (!existsSync(file)) return undefined;
  const a = JSON.parse(readFileSync(file, 'utf8'));
  if (a?.v !== 1 || typeof a.user !== 'string' || typeof a.salt !== 'string' || typeof a.hash !== 'string') throw new Error(`${file} does not hold an admin account`);
  return a;
}
function writeAccount(file, a) {
  writeFileSync(`${file}.tmp`, JSON.stringify(a), { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}
async function hashOf(password, salt) {
  const { N, r, p, keylen } = SCRYPT;
  return (await scrypt(password, Buffer.from(salt, 'base64url'), keylen, { N, r, p })).toString('base64url');
}
async function withPassword(a, password) {
  const salt = randomBytes(16).toString('base64url');
  return { ...a, salt, hash: await hashOf(password, salt), scrypt: SCRYPT };
}
async function passwordIs(a, password) {
  const got = Buffer.from(await hashOf(password, a.salt), 'base64url');
  const want = Buffer.from(a.hash, 'base64url');
  return got.length === want.length && timingSafeEqual(got, want);
}

// A one-time reset link: the token's hash kept in admin.json for 15 minutes.
export function resetPassword({ file, host, now = Date.now }) {
  const a = readAccount(file);
  if (!a) throw new Error('no admin account yet: start the relay with ADMIN_USER and ADMIN_PASSWORD');
  const token = randomBytes(32).toString('base64url');
  writeAccount(file, { ...a, reset: { hash: sha(token), expires: now() + LIMITS.resetMs } });
  return `https://${host}/admin/reset#${token}`;
}

const STYLE = 'body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#222;background:#faf9f5}'
  + 'h1{font-size:1.3rem}h2{font-size:1.1rem;margin-top:2rem}table{border-collapse:collapse;width:100%}'
  + 'td,th{text-align:left;vertical-align:top;padding:.35rem .5rem;border-bottom:1px solid #ddd}'
  + 'form{display:inline}label{display:block;margin:.5rem 0}input{font:inherit}pre{margin:0;white-space:pre-wrap;font-size:.85rem}'
  + '.code{font-family:ui-monospace,monospace;font-size:1.1rem}.note{color:#666}';
// The reset page's script: the token travels after `#`, which no browser sends.
const RESET_SCRIPT = "document.getElementById('token').value=location.hash.slice(1);";
const csp = (script) => `default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'${script ? `; script-src 'sha256-${createHash('sha256').update(script).digest('base64')}'` : ''}`;
const page = (title, body, script) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${STYLE}</style></head><body>
${body}${script ? `\n<script>${script}</script>` : ''}
</body></html>
`;
const button = (action, id, label) => `<form method="post" action="/admin/${action}"><input type="hidden" name="id" value="${esc(id)}"><button>${label}</button></form>`;

// `machines` is machines.mjs's admin side; `relay` is byokit's Relay, of
// which `hosts` and `revoke` are used. Rejects when the account cannot be
// set up. `request(req, res)` answers true when the request was this module's.
export async function createAdmin({ file, env, machines, relay, now = Date.now, trustProxy = false, log = () => {} }) {
  const host = env.RELAY_HOST;
  if (!host) throw new Error('RELAY_HOST is required: the relay\'s domain, for the admin page\'s Origin check and reset link');
  const origin = `https://${host}`;
  if (!existsSync(file)) {
    const user = env.ADMIN_USER, password = env.ADMIN_PASSWORD;
    if (!user || !USER.test(user) || !password || password.length < LIMITS.password) {
      throw new Error(`no admin account yet: set ADMIN_USER and ADMIN_PASSWORD (at least ${LIMITS.password} characters) in the relay's environment`);
    }
    writeAccount(file, await withPassword({ v: 1, user }, password));
    log(`admin: account ${user} set up`);
  }
  readAccount(file);

  // token -> expiry, in memory.
  const sessions = new Map();
  // Wrong sign-ins: per client address, and for all of them together as a
  // backstop. One sign-in is checked at a time, so a burst cannot pass the
  // count while its hashes are being computed.
  const lockouts = new Map(); // address -> {failures: [times], until}
  const everyone = { failures: [], until: 0 };
  let signingIn = false;

  function signedIn(req) {
    const m = new RegExp(`(?:^|;\\s*)${COOKIE}=([A-Za-z0-9_-]{43})(?:;|$)`).exec(req.headers.cookie ?? '');
    const until = m && sessions.get(m[1]);
    if (!until) return undefined;
    if (now() >= until) { sessions.delete(m[1]); return undefined; }
    return m[1];
  }
  function html(res, status, title, body, script) {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'same-origin', 'x-frame-options': 'DENY', 'content-security-policy': csp(script) }).end(page(title, body, script));
  }
  const back = (res, headers = {}) => res.writeHead(303, { location: '/admin', 'cache-control': 'no-store', ...headers }).end();
  const message = (res, status, text) => html(res, status, 'Relay admin', `<h1>Relay admin</h1><p>${esc(text)}</p><p><a href="/admin">Back</a></p>`);

  async function form(req) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > LIMITS.body) { req.resume(); return undefined; }
      chunks.push(c);
    }
    return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
  }

  const signInPage = (note = '') => `<h1>Relay admin</h1>${note ? `<p>${esc(note)}</p>` : ''}
<h2>Sign in</h2><form method="post" action="/admin/sign-in">
<label>Name <input name="user" autocomplete="username" required></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button>Sign in</button></form>`;

  function mainPage() {
    const known = new Map(machines.machines().map((m) => [m.id, m]));
    const hosts = relay.hosts();
    const reqs = machines.requests().map((r) => `<tr><td>${esc(r.name)}</td><td class="code">${esc(`${r.code.slice(0, 4)}-${r.code.slice(4)}`)}</td>`
      + `<td><pre>${esc(JSON.stringify(r.details, null, 1))}</pre></td><td>${esc(r.from)}</td><td>${esc(when(r.asked))}</td>`
      + `<td>${button('approve', r.id, 'Approve')} ${button('refuse', r.id, 'Refuse')}</td></tr>`).join('\n');
    const ms = [...known.values()].map((m) => {
      const people = hosts.filter((h) => h.meta?.machine === m.id)
        .map((h) => `${esc(h.meta?.person ?? h.name)} (${h.online ? 'online' : 'offline'}, ${h.devices} device${h.devices === 1 ? '' : 's'})`).join('<br>');
      return `<tr><td>${esc(m.name)}<br><span class="note">${esc(m.id)}</span></td><td>${people || '<span class="note">none yet</span>'}</td>`
        + `<td>${esc(when(m.joined))}</td><td>${button('remove-machine', m.id, 'Remove')}</td></tr>`;
    }).join('\n');
    const others = hosts.filter((h) => !known.has(h.meta?.machine)).map((h) => `<tr><td>${esc(h.name)}<br><span class="note">${esc(h.id)}</span></td>`
      + `<td>${h.online ? 'online' : 'offline'}, ${h.devices} device${h.devices === 1 ? '' : 's'}</td><td>${button('remove-host', h.id, 'Remove')}</td></tr>`).join('\n');
    const table = (head, rows, empty) => rows ? `<table><tr>${head.map((h) => `<th>${h}</th>`).join('')}</tr>\n${rows}</table>` : `<p class="note">${empty}</p>`;
    return `<h1>Relay admin: ${esc(host)}</h1>
<h2>Requests</h2>${table(['Name', 'Code', 'Details', 'From', 'Asked', ''], reqs, 'No machine is waiting.')}
<h2>Machines</h2>${table(['Name', 'People', 'Joined', ''], ms, 'No machine has joined.')}
<h2>Other hosts</h2>${table(['Name', 'State', ''], others, 'None.')}
<h2>Account</h2><form method="post" action="/admin/password">
<label>Current password <input name="current" type="password" autocomplete="current-password" required></label>
<label>New password <input name="password" type="password" autocomplete="new-password" minlength="${LIMITS.password}" required></label>
<label>Again <input name="again" type="password" autocomplete="new-password" minlength="${LIMITS.password}" required></label>
<button>Change password</button></form>
<p><form method="post" action="/admin/sign-out"><button>Sign out</button></form></p>`;
  }

  const resetPage = `<h1>Relay admin</h1><h2>Set a new password</h2><form method="post" action="/admin/reset">
<input type="hidden" id="token" name="token">
<label>Name (empty keeps it) <input name="user" autocomplete="username"></label>
<label>New password <input name="password" type="password" autocomplete="new-password" minlength="${LIMITS.password}" required></label>
<label>Again <input name="again" type="password" autocomplete="new-password" minlength="${LIMITS.password}" required></label>
<button>Set password</button></form>`;

  const goodPassword = (f) => (f.get('password') ?? '').length >= LIMITS.password && f.get('password') === f.get('again');

  async function signIn(req, res) {
    const f = await form(req);
    const t = now();
    const address = clientAddress(req, trustProxy);
    for (const [a, l] of lockouts) if (t >= l.until && !l.failures.some((x) => t - x < LIMITS.failureWindowMs)) lockouts.delete(a);
    const mine = lockouts.get(address) ?? { failures: [], until: 0 };
    if (t < mine.until || t < everyone.until) return html(res, 429, 'Relay admin', signInPage('Sign-in is locked for a quarter of an hour after too many wrong passwords.'));
    if (signingIn) return html(res, 429, 'Relay admin', signInPage('Another sign-in is being checked; try again.'));
    signingIn = true;
    try {
      // The attempt counts as wrong until the password is found right.
      const record = (l, limit) => {
        l.failures = [...l.failures.filter((x) => t - x < LIMITS.failureWindowMs), t];
        if (l.failures.length >= limit) { l.until = t + LIMITS.lockMs; return true; }
        return false;
      };
      const before = { mine: { ...mine }, everyone: { ...everyone } };
      if (record(mine, LIMITS.failures)) log(`admin: sign-in locked for ${address} after wrong passwords`);
      if (record(everyone, LIMITS.globalFailures)) log('admin: sign-in locked for everyone after wrong passwords');
      lockouts.set(address, mine);
      const a = readAccount(file);
      const user = f?.get('user') ?? '', password = f?.get('password') ?? '';
      // The hash is computed for a wrong name too, so both take as long.
      const right = await passwordIs(a, password) && user === a.user;
      if (!right) return html(res, 403, 'Relay admin', signInPage('Wrong name or password.'));
      // Right after all: the attempt was no failure, and a lock it set is undone.
      Object.assign(mine, before.mine);
      Object.assign(everyone, before.everyone);
      const token = randomBytes(32).toString('base64url');
      sessions.set(token, t + LIMITS.sessionMs);
      back(res, { 'set-cookie': `${COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/admin; Max-Age=${LIMITS.sessionMs / 1000}` });
    } finally { signingIn = false; }
  }

  async function reset(req, res) {
    const f = await form(req);
    const a = readAccount(file);
    const token = f?.get('token') ?? '';
    if (!a.reset || now() > a.reset.expires || !TOKEN.test(token) || !sameHex(sha(token), a.reset.hash)) return message(res, 403, 'This link is used, expired or wrong. Run reset-password on the relay\'s server again.');
    const user = f.get('user') || a.user;
    if (!USER.test(user) || !goodPassword(f)) return message(res, 400, `The name or the password cannot be used: at least ${LIMITS.password} characters, the same twice.`);
    // The link is spent before the hash is computed, so a second reset at the same moment finds none.
    const { reset: _, ...rest } = a;
    writeAccount(file, rest);
    writeAccount(file, await withPassword({ ...rest, user }, f.get('password')));
    sessions.clear();
    lockouts.clear();
    everyone.until = 0;
    everyone.failures = [];
    log(`admin: password of ${user} reset`);
    back(res);
  }

  async function signedInPost(req, res, what, session) {
    const f = await form(req);
    if (!f) return message(res, 400, 'Too long.');
    const id = f.get('id') ?? '';
    try {
      if (what === 'sign-out') { sessions.delete(session); return back(res); }
      if (what === 'approve') await machines.approve(id);
      else if (what === 'refuse') await machines.refuse(id);
      else if (what === 'remove-machine') await machines.remove(id);
      else if (what === 'remove-host') {
        const h = relay.hosts().find((x) => x.id === id);
        const known = new Set(machines.machines().map((m) => m.id));
        if (!h || known.has(h.meta?.machine)) return message(res, 400, 'No such host, or it is a machine\'s: remove the machine.');
        await relay.revoke(id);
        log(`admin: host ${h.name} ${id} removed`);
      } else if (what === 'password') {
        const a = readAccount(file);
        if (!await passwordIs(a, f.get('current') ?? '')) return message(res, 403, 'The current password is wrong.');
        if (!goodPassword(f)) return message(res, 400, `The new password needs at least ${LIMITS.password} characters, the same twice.`);
        // A reset link not yet used is dropped with the old password.
        const { reset: _, ...rest } = a;
        writeAccount(file, await withPassword(rest, f.get('password')));
        for (const s of sessions.keys()) if (s !== session) sessions.delete(s);
        log(`admin: password of ${a.user} changed`);
      } else return message(res, 404, 'Not found.');
    } catch (e) { return message(res, 400, String(e?.message ?? e)); }
    back(res);
  }

  async function request(req, res) {
    const path = new URL(req.url ?? '/', 'http://relay').pathname;
    if (path !== '/admin' && !path.startsWith('/admin/')) return false;
    if (req.method === 'GET' || req.method === 'HEAD') {
      if (path === '/admin') html(res, 200, 'Relay admin', signedIn(req) ? mainPage() : signInPage());
      else if (path === '/admin/reset') html(res, 200, 'Relay admin', resetPage, RESET_SCRIPT);
      else message(res, 404, 'Not found.');
      return true;
    }
    if (req.method !== 'POST') { message(res, 405, 'Not allowed.'); return true; }
    if (req.headers.origin !== origin) { req.resume(); message(res, 403, 'Refused.'); return true; }
    const what = path.slice('/admin/'.length);
    if (what === 'sign-in') { await signIn(req, res); return true; }
    if (what === 'reset') { await reset(req, res); return true; }
    const session = signedIn(req);
    if (!session) { req.resume(); message(res, 403, 'Sign in first.'); return true; }
    await signedInPost(req, res, what, session);
    return true;
  }

  return { request };
}

// `node admin.mjs reset-password`, run where the relay runs (its RELAY_STATE
// and RELAY_HOST): the link is printed, valid 15 minutes, used once.
if (process.argv[1] && realpathSync(process.argv[1]) === realpathSync(import.meta.filename)) {
  try {
    if (process.argv[2] !== 'reset-password') throw new Error('usage: node admin.mjs reset-password');
    if (!process.env.RELAY_STATE || !process.env.RELAY_HOST) throw new Error('RELAY_STATE and RELAY_HOST are required');
    console.log(resetPassword({ file: join(dirname(process.env.RELAY_STATE), 'admin.json'), host: process.env.RELAY_HOST }));
  } catch (e) {
    console.error(String(e?.message ?? e));
    process.exit(1);
  }
}
