// The shared relay: @byokit/relay on a plain Node HTTP server, with the blob
// endpoint of the Feyn client design (section 6.3) in the same process. The
// relay routes ciphertext between machines and devices and keeps no
// messages; the blob endpoint keeps ciphertext files for one fetch or a day;
// the OAuth callback keeps a code, in memory, for one fetch or ten minutes;
// the statement routes serve the owner's signed statement from the state
// directory (relay distribution design, section 3); the join routes let a
// machine join and ask for its people's tickets (section 4); the admin page
// lets the operator answer them (section 5).
//
// `relay.attach(server)` answers 404 for every path the relay does not
// know, so this file routes requests itself: the statement, the join
// routes, the admin page, the OAuth callback and blobs first, then the relay.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Relay } from '@byokit/relay';
import { createBlobs } from './blobs.mjs';
import { createOauth } from './oauth.mjs';
import { createStatement } from './statement.mjs';
import { createMachines } from './machines.mjs';
import { createAdmin } from './admin.mjs';

const PORT = Number(process.env.RELAY_PORT ?? 7300);
const HOST = process.env.LISTEN_HOST ?? '127.0.0.1';
const STATE = process.env.RELAY_STATE;
// Where blobs are kept. Unset: the relay runs as it did without them.
const BLOB_DIR = process.env.BLOB_DIR;
if (!STATE || !process.env.RELAY_OWNER_TOKEN) throw new Error('RELAY_STATE and RELAY_OWNER_TOKEN are required');

const relay = await Relay.open({
  store: {
    load: () => existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : undefined,
    save: (s) => { writeFileSync(STATE + '.tmp', JSON.stringify(s), { mode: 0o600 }); renameSync(STATE + '.tmp', STATE); },
  },
  ownerToken: process.env.RELAY_OWNER_TOKEN,
  trustProxy: process.env.TRUST_PROXY === '1',
});
const log = (line) => console.log(`${new Date().toISOString()} ${line}`);
// Machines that joined, and their requests, beside the relay's state.
const machines = createMachines({ file: join(dirname(STATE), 'machines.json'), relay, trustProxy: process.env.TRUST_PROXY === '1', log });
// The operator's page; the account is made from ADMIN_USER and
// ADMIN_PASSWORD at first start, and the relay refuses to start without it.
const admin = await createAdmin({ file: join(dirname(STATE), 'admin.json'), env: process.env, machines, relay, log });
const blobs = BLOB_DIR
  ? await createBlobs({
      dir: BLOB_DIR,
      // The endpoint's key pair lives beside the relay's state.
      keyFile: process.env.BLOB_KEY ?? join(dirname(STATE), 'blob-key.json'),
      hosts: () => relay.hosts(),
      log,
    })
  : undefined;

// The owner's statement for this relay, read from disk on every request.
const statement = createStatement({ dir: dirname(STATE) });
console.log(statement.describe());

// Where a service's OAuth sign-in comes back to: a code kept for one fetch.
const oauth = createOauth();

const server = createServer();
// Node gives a request five minutes to arrive whole; 51 MiB from a phone can
// take longer.
server.requestTimeout = 30 * 60_000;
server.on('upgrade', (req, socket, head) => { if (!relay.upgrade(req, socket, head)) socket.destroy(); });
server.on('request', (req, res) => {
  void (async () => {
    if (await statement.request(req, res)) return;
    if (await machines.request(req, res)) return;
    if (await admin.request(req, res)) return;
    if (await oauth.request(req, res)) return;
    if (blobs && await blobs.request(req, res)) return;
    if (await relay.request(req, res)) return;
    res.writeHead(404, { 'content-type': 'application/json' }).end(JSON.stringify({ error: 'not found' }));
  })().catch(() => { if (!res.headersSent) res.writeHead(500).end(); else res.destroy(); });
});
server.listen(PORT, HOST, () => console.log(`relay listening ${HOST}:${PORT}${blobs ? ` blobs ${BLOB_DIR}` : ''}`));
process.on('SIGTERM', () => { blobs?.close(); relay.close(); server.closeAllConnections(); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 500); });
