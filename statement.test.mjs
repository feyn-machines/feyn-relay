// The relay's statement (relay distribution design, section 3), on loopback:
// the two files of the state directory served byte for byte, read again on
// every request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStatement } from './statement.mjs';

// What `sign-relay` writes: no trailing newline. The signature is any bytes here.
const JSON_BYTES = Buffer.from('{"v":1,"relay":"relay.example.com","issued":"2026-10-22","expires":"2027-10-22"}');
const SIG_BYTES = Buffer.from([0x89, 0x02, 0x33, 0x00, 0xff, 0x0a, 0x0d, 0x80]);

async function setup(t, files = { json: JSON_BYTES, sig: SIG_BYTES }) {
  const dir = mkdtempSync(join(tmpdir(), 'feyn-statement-'));
  if (files.json) writeFileSync(join(dir, 'relay-statement.json'), files.json);
  if (files.sig) writeFileSync(join(dir, 'relay-statement.json.sig'), files.sig);
  const statement = createStatement({ dir });
  const server = createServer((req, res) => {
    void statement.request(req, res).then((done) => { if (!done) res.writeHead(404).end('not ours'); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); rmSync(dir, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const call = async (path, method = 'GET') => {
    const r = await fetch(base + path, { method });
    return { status: r.status, type: r.headers.get('content-type'), length: r.headers.get('content-length'), body: Buffer.from(await r.arrayBuffer()) };
  };
  return { dir, call };
}

test('both routes serve the stored bytes unchanged', async (t) => {
  const s = await setup(t);
  const json = await s.call('/feyn/v1/relay');
  assert.deepEqual([json.status, json.type], [200, 'application/json']);
  assert.ok(json.body.equals(JSON_BYTES));
  const sig = await s.call('/feyn/v1/relay.sig');
  assert.deepEqual([sig.status, sig.type], [200, 'application/octet-stream']);
  assert.ok(sig.body.equals(SIG_BYTES));
});

test('HEAD answers as GET does, with no body', async (t) => {
  const s = await setup(t);
  const head = await s.call('/feyn/v1/relay', 'HEAD');
  assert.deepEqual([head.status, head.type, head.length, head.body.length], [200, 'application/json', String(JSON_BYTES.length), 0]);
  assert.equal((await s.call('/feyn/v1/relay.sig', 'HEAD')).status, 200);
});

test('a missing file is 404, each on its own', async (t) => {
  const none = await setup(t, {});
  assert.equal((await none.call('/feyn/v1/relay')).status, 404);
  assert.equal((await none.call('/feyn/v1/relay.sig')).status, 404);
  const noSig = await setup(t, { json: JSON_BYTES });
  assert.equal((await noSig.call('/feyn/v1/relay')).status, 200);
  assert.equal((await noSig.call('/feyn/v1/relay.sig')).status, 404);
});

test('the files are read again on each request: a new statement needs no restart', async (t) => {
  const s = await setup(t, {});
  assert.equal((await s.call('/feyn/v1/relay')).status, 404);
  const next = Buffer.from('{"v":1,"relay":"relay.example.com","issued":"2027-10-01","expires":"2028-10-01"}');
  writeFileSync(join(s.dir, 'relay-statement.json'), next);
  writeFileSync(join(s.dir, 'relay-statement.json.sig'), SIG_BYTES);
  assert.ok((await s.call('/feyn/v1/relay')).body.equals(next));
  unlinkSync(join(s.dir, 'relay-statement.json.sig'));
  assert.equal((await s.call('/feyn/v1/relay.sig')).status, 404);
});

test('other methods are refused, other paths are not this module\'s', async (t) => {
  const s = await setup(t);
  assert.equal((await s.call('/feyn/v1/relay', 'POST')).status, 405);
  assert.equal((await s.call('/feyn/v1/relay.json')).body.toString(), 'not ours');
  assert.equal((await s.call('/feyn/v1/relay/')).body.toString(), 'not ours');
});

test('describe: the relay and its expiry, or that it is missing', async (t) => {
  const s = await setup(t);
  assert.equal(createStatement({ dir: s.dir }).describe(), 'statement: relay.example.com until 2027-10-22');
  const none = await setup(t, {});
  assert.equal(createStatement({ dir: none.dir }).describe(), 'statement: missing, machines will refuse this relay');
  const noSig = await setup(t, { json: JSON_BYTES });
  assert.equal(createStatement({ dir: noSig.dir }).describe(), 'statement: missing, machines will refuse this relay');
  const bad = await setup(t, { json: Buffer.from('not json'), sig: SIG_BYTES });
  assert.equal(createStatement({ dir: bad.dir }).describe(), 'statement: unreadable, machines will refuse this relay');
});
