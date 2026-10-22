// The probe of the relay distribution plan, task 1 (feyn-os, spec 4.6): what
// byokit keeps of a host across `leave()` and a new enrolment with the same
// key. A relay on loopback with its state in memory; host H enrolled with a
// ticket; device D paired with H through the relay's short code; then H
// leaves, a new ticket is minted, and H starts again with the same key.
//
// Finding: H's id is the same (it is a hash of the key); D reaches H again
// with the grant it already holds, without pairing. A device's grant lives
// on the host and on the device, not on the relay. What `leave()` does take
// away is the host's push addresses; a device subscribes again. And a host
// still enrolled ignores a new ticket: its metadata stays as it was, so a
// host is re-enrolled with new `meta` only after it has left.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { DeviceLink, Host, keyPair, pairWithCode } from '@byokit/link';
import { Relay, RelayClient } from '@byokit/relay';
import { findHost } from '@byokit/relay/device';

const until = async (check, what) => {
  for (let i = 0; i < 400; i++) { if (check()) return; await new Promise((r) => setTimeout(r, 10)); }
  assert.fail(`timed out waiting for ${what}`);
};

async function setup(t) {
  let saved;
  const relay = await Relay.open({ store: { load: () => saved, save: (s) => { saved = structuredClone(s); } } });
  const server = createServer();
  relay.attach(server);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const hostUrl = `ws://127.0.0.1:${server.address().port}/relay/v1/host`;
  const open = [];
  t.after(async () => { for (const c of open) c.stop(); relay.close(); server.closeAllConnections(); await new Promise((r) => server.close(r)); });
  // One connection of H to the relay; resolves once the relay says ready or refused.
  const connect = async (host, enrol) => {
    const client = new RelayClient(host, { url: hostUrl, enrol, pingMs: 60_000 });
    open.push(client);
    await until(() => client.status === 'online' || client.status === 'refused', 'the host to connect');
    return client;
  };
  return { relay, base, connect, state: () => saved };
}

test('a host that leaves and enrols again with the same key keeps its id and its paired devices', async (t) => {
  const { relay, base, connect, state } = await setup(t);
  // The host's grants are kept in its own store, as a connector keeps them on disk.
  let grants = [];
  const host = await Host.open({
    keys: keyPair(), name: 'H',
    confirm: () => true,
    handle: (req) => ({ pong: req.op }),
    grants: { load: () => grants, save: (g) => { grants = g; } },
  });
  t.after(() => host.close());

  const first = await relay.enrolment({ name: 'm/one', meta: { machine: 'old' } });
  const c1 = await connect(host, first.token);
  assert.equal(c1.status, 'online');
  const id = c1.id;
  assert.deepEqual(relay.hosts().map((h) => [h.id, h.meta]), [[id, { machine: 'old' }]]);

  // D pairs with H through the relay, as the client does.
  const { code: short } = await c1.code();
  const url = await findHost(base, short);
  assert.equal(url, `${base.replace('http', 'ws')}/link/v1/${id}`);
  const grant = await pairWithCode(url, host.code({ role: 'control' }).code, { name: 'D' });
  const d1 = new DeviceLink(grant);
  assert.deepEqual(await d1.request('ping'), { pong: 'ping' });
  d1.stop();
  assert.equal(grants.length, 1);
  // D's push address, which a device sends over the link and the host stores on the relay.
  await c1.subscribe(grants[0].id, { expo: 'ExponentPushToken[probe]' });
  assert.equal(state().push.length, 1);

  // A host already enrolled ignores a new ticket: its metadata is not replaced.
  const ignored = await relay.enrolment({ name: 'm/one', meta: { machine: 'new' } });
  c1.stop();
  const c1b = await connect(host, ignored.token);
  assert.equal(c1b.status, 'online');
  assert.deepEqual(relay.hosts()[0].meta, { machine: 'old' });

  // H leaves the relay: it is forgotten there.
  await c1b.leave();
  assert.deepEqual(relay.hosts(), []);
  // Its push addresses went with it.
  assert.equal(state().push.length, 0);
  // Without a new ticket it is refused.
  const refused = await connect(host, undefined);
  assert.equal(refused.status, 'refused');

  // A new ticket, the same key: the same id, the new metadata.
  const second = await relay.enrolment({ name: 'm/one', meta: { machine: 'new' } });
  const c2 = await connect(host, second.token);
  assert.equal(c2.status, 'online');
  assert.equal(c2.id, id);
  assert.deepEqual(relay.hosts().map((h) => [h.id, h.meta]), [[id, { machine: 'new' }]]);

  // D reaches H with the grant it already held: no pairing again.
  assert.equal(grants.length, 1);
  const d2 = new DeviceLink(grant);
  assert.deepEqual(await d2.request('ping'), { pong: 'ping' });
  d2.stop();
});
