# feyn-relay

The relay deployment of the remote client: `@byokit/relay` on a plain Node
HTTP server, and, in the same process, the blob endpoint of the
Feyn client design (feyn-os, `docs/superpowers/specs/2026-10-12-feyn-client-design.md`),
section 6.3. The relay routes ciphertext between machines and devices and
keeps no messages. The blob endpoint keeps ciphertext files, each for one
fetch or 24 hours. Nothing here holds a key that opens anything.

Status: written and tested on loopback on 2026-10-12. **Not deployed.** What
runs on the relay server today is the mount file without the blob routes;
that copy stays in the
probe's record (feyn-os, `docs/research/2026-10-11-byokit-probe/relay-deploy/`)
as what was deployed on 2026-10-11. Whether the Cloudflare tunnel in front
of the relay passes a request body of 51 MiB has not been checked.

```bash
npm install --ignore-scripts
npm test            # node --test: blobs.test.mjs and relay.test.mjs, loopback only
```

## Files

| Path | What |
| --- | --- |
| `relay.mjs` | The mount file. `relay.attach(server)` answers 404 for every path the relay does not know, so this file routes requests itself: the blob routes first, then `relay.request`, then 404; upgrades go to `relay.upgrade`. |
| `blobs.mjs` | The blob endpoint: its key pair, the token check, streaming to and from disk, the limits, the sweep, CORS. No dependency beyond Node. |
| `blobs.test.mjs` | The endpoint on a loopback server with a fake clock and a fake host list. |
| `relay.test.mjs` | `relay.mjs` as a child process: both sets of routes and the upgrade on one port. |
| `probe/reenrol.test.mjs` | byokit across a host's `leave()` and a new enrolment with the same key (see "Re-enrolment"). |
| `Dockerfile`, `compose.yml` | `node:24-slim`, `npm ci --ignore-scripts`; read-only root, all capabilities dropped, 256 MB, bound to `127.0.0.1:7300`; volumes `./state` and `./blobs`. |
| `package-lock.json` | `@byokit/relay` 0.6.0 and everything under it, at the versions of the lockfile deployed on 2026-10-11. |

## The blob routes

| Route | Does |
| --- | --- |
| `GET /feyn/v1/blobs/key` | `{key}`: the endpoint's X25519 public key, base64url |
| `PUT /feyn/v1/blobs/<address>` | checks the token; `content-length` must be the size the token names and at most 51 MiB; streams the body to disk; `201`. An address that is there already: `200`, the body dropped |
| `GET /feyn/v1/blobs/<address>` | streams the file and **deletes it when the response has been sent whole**; `404` when absent; `503` with `retry-after` while another fetch of it is under way |
| `OPTIONS` on both | CORS: `access-control-allow-origin: *`, methods `GET, PUT, OPTIONS`, headers `content-type` and the three `x-feyn-*` |

`<address>` is 32 random bytes in base64url (43 characters), made by a
host's connector. Knowing it is what allows a fetch; what is fetched is
ciphertext.

| Answer to a `PUT` | When |
| --- | --- |
| `201` | stored |
| `200` | the address was there already |
| `401` | one of the three headers is missing |
| `403` | the host is not enrolled (or was revoked), the expiry has passed or is more than 15 minutes ahead, or the token does not match the address, the size and the expiry |
| `411` | no `content-length` |
| `413` | over 51 MiB (the connection is closed without reading the body), or this host's unfetched blobs would pass 500 MiB |
| `507` | all blobs would pass 2 GiB, or the disk is full |

### Who may upload

The endpoint makes one X25519 key pair at first start and keeps it in the
state directory (`blob-key.json`, mode `0600`, beside the relay's state
file). An upload carries `x-feyn-host` (the host's id at the relay),
`x-feyn-expires` (Unix seconds) and `x-feyn-token`, the base64url of

```text
HMAC-SHA256( X25519(host secret key, endpoint public key),
             "feyn-blob-v1" ‖ 0 ‖ address ‖ 0 ‖ size ‖ 0 ‖ expires )
```

where `0` is one zero byte, `address` is the base64url text of the path,
and `size` (the `content-length`) and `expires` are in decimal. The endpoint
looks the host up in `relay.hosts()`, computes the same shared secret from
the host's public key and its own secret key, and compares in constant
time. Only the holder of an enrolled host's secret key can make a token, for
one address and one size; a revoked host's tokens stop at once. A
connector hands such headers to its person's paired devices
(`attachment.upload`) and uses them itself for outbound files.

### What is kept, and what the server learns

A file `<blob dir>/<address>.<host id>` per unfetched blob, and
`<name>.part` while one is arriving; the file's size and time are the
record. At start the directory is read back, part files are removed, and
anything older than 24 hours is swept; the sweep runs again every ten
minutes. The log has one line per upload and fetch with the host id, the
size and the status, and never an address.

The server learns that a person-on-machine moved a file of about that size
at that time. It does not learn a name, a type, a key or any content.
Sizes are not padded.

"Sent whole" is the moment the last byte has left this process. A proxy in
front can still lose the tail on its own leg; the side that fetched then
asks for the file to be uploaded again.

## Re-enrolment

What byokit 0.6.0 keeps of a host across `leave()` and a new enrolment with
the same key, checked on loopback on 2026-10-22 by
`probe/reenrol.test.mjs` (the relay distribution plan's task 1; feyn-os,
spec `2026-10-22-relay-distribution-design.md`, section 4.6):

- The host's id is unchanged: it is a hash of the host's key.
- A device paired before reaches the host again with the grant it already
  holds; it does **not** pair again. A grant lives on the host (its grant
  store) and on the device; the relay only routes by host id.
- `leave()` removes the host's push addresses on the relay (byokit's
  `removeHost`); a device's push address is stored again when it next
  subscribes.
- A host that is still enrolled ignores a new ticket: byokit only reads
  `enrol` for a host it does not know, so the host keeps its old name and
  metadata. A host enrolled by hand (no `meta.machine`) gets the new
  metadata only by leaving first and then enrolling with the new ticket.

## Configuration

| Variable | Meaning | Default |
| --- | --- | --- |
| `RELAY_STATE` | the relay's state file | required |
| `RELAY_OWNER_TOKEN` | the bearer token of the owner routes (in `.env`) | required |
| `RELAY_PORT`, `LISTEN_HOST` | where to listen | `7300`, `127.0.0.1` |
| `TRUST_PROXY` | `1` to take the client address from `X-Forwarded-For` | off |
| `BLOB_DIR` | where blobs are kept; unset, there are no blob routes and the relay runs as before | unset |
| `BLOB_KEY` | the endpoint's key file | `blob-key.json` beside `RELAY_STATE` |

A request may take up to 30 minutes to arrive whole (Node's default is
five), so that 51 MiB can come from a phone.

## Deploying (not done yet; step 1 of the plan's verification)

On the relay server, in the deployment's directory (`~/feyn-relay` since
2026-10-11), keeping `.env` and `state/` as they are:

1. Copy `relay.mjs`, `blobs.mjs`, `package.json`, `package-lock.json`,
   `Dockerfile`, `.dockerignore` and `compose.yml` over the old files.
2. `mkdir -p blobs` and give it to the container's user, as `state/` is
   (`node`, uid 1000).
3. `docker compose build && docker compose up -d`.
4. Check: `curl -s http://127.0.0.1:7300/feyn/v1/blobs/key` on the server
   and the same path through the tunnel; the owner's host list still shows
   the enrolled hosts online; `state/blob-key.json` exists with mode `0600`.
5. From the experiment host, upload 51 MiB with a token made there and fetch
   it once (the plan's step J1); this is the check of the tunnel's body
   limit.

Losing `state/blob-key.json` is harmless: a new key pair is made, and
connectors read the new public key within ten minutes, or at once when an
upload of their own is refused. Removing `blobs/` loses only files nobody
had fetched yet; the sender uploads again.

## Untested until the server

- The container: the `./blobs` volume's ownership, the read-only root with
  two writable volumes, memory under a 51 MiB stream.
- The Cloudflare tunnel with a 51 MiB request body and a slow upload.
- A browser's preflight and `PUT` from the app's origin through the tunnel.
