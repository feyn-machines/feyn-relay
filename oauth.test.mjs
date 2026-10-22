// The OAuth callback of the person home and connections design, section 6a,
// on loopback: a code is kept under its state, for one fetch and ten minutes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createOauth, LIMITS } from './oauth.mjs';

const state = (c = 'a') => c.repeat(43);

async function setup(t, o = {}) {
  let clock = 1_000_000;
  const oauth = createOauth({ now: () => clock, ...o });
  const server = createServer((req, res) => {
    void oauth.request(req, res).then((done) => { if (!done) res.writeHead(404).end('{"error":"not found"}'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = async (path) => {
    const r = await fetch(base + path);
    const text = await r.text();
    return { status: r.status, type: r.headers.get('content-type') ?? '', cache: r.headers.get('cache-control'), text, json: () => JSON.parse(text) };
  };
  return { oauth, get, tick: (ms) => { clock += ms; } };
}

test('a code that came back is fetched once by whoever knows its state', async (t) => {
  const s = await setup(t);
  const page = await s.get(`/oauth/google/callback?code=4%2F0Abc-def_123&state=${state()}&scope=x`);
  assert.equal(page.status, 200);
  assert.match(page.type, /^text\/html/);
  assert.equal(page.cache, 'no-store');
  assert.match(page.text, /Feyn/);
  assert.ok(!page.text.includes('4/0Abc'), 'the page does not show the code');
  const first = await s.get(`/oauth/google/code?state=${state()}`);
  assert.deepEqual([first.status, first.json(), first.cache], [200, { code: '4/0Abc-def_123' }, 'no-store']);
  const second = await s.get(`/oauth/google/code?state=${state()}`);
  assert.deepEqual([second.status, second.json()], [404, { error: 'not_found' }]);
});

test('nothing yet, another state, another service: not found', async (t) => {
  const s = await setup(t);
  assert.equal((await s.get(`/oauth/google/code?state=${state()}`)).status, 404);
  await s.get(`/oauth/google/callback?code=c1&state=${state()}`);
  assert.equal((await s.get(`/oauth/google/code?state=${state('b')}`)).status, 404);
  assert.equal((await s.get(`/oauth/other/code?state=${state()}`)).status, 404);
  assert.equal((await s.get(`/oauth/google/code?state=${state()}`)).status, 200);
});

test('a refusal at the service is carried as an error, without a code', async (t) => {
  const s = await setup(t);
  const page = await s.get(`/oauth/google/callback?error=access_denied&state=${state()}`);
  assert.equal(page.status, 200);
  assert.deepEqual((await s.get(`/oauth/google/code?state=${state()}`)).json(), { error: 'access_denied' });
});

test('a code is kept ten minutes', async (t) => {
  const s = await setup(t);
  await s.get(`/oauth/google/callback?code=c1&state=${state()}`);
  s.tick(LIMITS.keepMs - 1);
  await s.get(`/oauth/google/callback?code=c2&state=${state('b')}`);
  s.tick(2);
  assert.equal((await s.get(`/oauth/google/code?state=${state()}`)).status, 404);
  assert.deepEqual((await s.get(`/oauth/google/code?state=${state('b')}`)).json(), { code: 'c2' });
});

test('what is not a callback as a service makes one is refused and kept nowhere', async (t) => {
  const s = await setup(t);
  for (const q of ['code=c', `code=c&state=short`, `state=${state()}`, `code=${'x'.repeat(LIMITS.codeChars + 1)}&state=${state()}`,
    `code=c&state=${state().slice(0, 42)}!`, `error=${'e'.repeat(101)}&state=${state()}`]) {
    assert.equal((await s.get(`/oauth/google/callback?${q}`)).status, 400, q);
  }
  assert.equal((await s.get('/oauth/Google/callback?code=c&state=' + state())).status, 404, 'a service name is lowercase letters');
  assert.equal(s.oauth.size(), 0);
  assert.equal((await s.get(`/oauth/google/code?state=${state()}`)).status, 404);
});

test('a second callback for a state does not replace the first', async (t) => {
  const s = await setup(t);
  await s.get(`/oauth/google/callback?code=first&state=${state()}`);
  assert.equal((await s.get(`/oauth/google/callback?code=second&state=${state()}`)).status, 400);
  assert.deepEqual((await s.get(`/oauth/google/code?state=${state()}`)).json(), { code: 'first' });
});

test('no more than the limit is kept at once: the oldest goes', async (t) => {
  const s = await setup(t, { max: 3 });
  for (const c of ['a', 'b', 'c', 'd']) { await s.get(`/oauth/google/callback?code=${c}&state=${state(c)}`); s.tick(1); }
  assert.equal(s.oauth.size(), 3);
  assert.equal((await s.get(`/oauth/google/code?state=${state('a')}`)).status, 404);
  assert.equal((await s.get(`/oauth/google/code?state=${state('d')}`)).status, 200);
});

test('only GET, and other paths are not this module\'s', async (t) => {
  const s = await setup(t);
  assert.equal((await s.get('/x')).status, 404);
  assert.equal((await s.get('/oauth/google')).status, 404);
  assert.equal((await s.get('/v1/hosts')).status, 404);
});
