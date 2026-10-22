# feyn-relay

The relay deployment of the remote client: `@byokit/relay` on a plain Node
HTTP server, and, in the same process, the blob endpoint of the
Feyn client design (feyn-os, `docs/superpowers/specs/2026-10-12-feyn-client-design.md`),
section 6.3, and the statement, join routes and admin page of the relay
distribution design (feyn-os, `docs/superpowers/specs/2026-10-22-relay-distribution-design.md`). The relay routes ciphertext between machines and devices and
keeps no messages. The blob endpoint keeps ciphertext files, each for one
fetch or 24 hours. Nothing here holds a key that opens anything.

Status: 0.3.0 written and tested on loopback on 2026-10-22; no image
pushed yet. **Not deployed.** What runs on the relay server today is the
mount file without the blob routes; that copy stays in the probe's record
(feyn-os, `docs/research/2026-10-11-byokit-probe/relay-deploy/`) as what was
deployed on 2026-10-11. Whether the Cloudflare tunnel in front of the relay
passes a request body of 51 MiB has not been checked.

```bash
npm install --ignore-scripts
npm test            # node --test: every *.test.mjs, loopback only
```

## Files

| Path | What |
| --- | --- |
| `relay.mjs` | The mount file. `relay.attach(server)` answers 404 for every path the relay does not know, so this file routes requests itself: the blob routes first, then `relay.request`, then 404; upgrades go to `relay.upgrade`. |
| `statement.mjs` | The statement routes: `relay-statement.json` and its `.sig` from the state directory, byte for byte, read on every request. |
| `machines.mjs` | The join routes: a machine's request and its code, the operator's answer, a person's ticket asked for with the machine's key, a machine leaving; `machines.json` beside the relay's state. |
| `address.mjs` | The client's address behind the proxy, for the join routes' and the admin page's limits. |
| `admin.mjs` | The admin page at `/admin`, and `node admin.mjs reset-password`. |
| `blobs.mjs` | The blob endpoint: its key pair, the token check, streaming to and from disk, the limits, the sweep, CORS. No dependency beyond Node. |
| `probe/reenrol.test.mjs` | byokit across a host's `leave()` and a new enrolment with the same key (see "Re-enrolment"). |
| `*.test.mjs` | Each module on loopback with a fake clock; `relay.test.mjs` runs `relay.mjs` as a child process. |
| `Dockerfile`, `compose.yml` | `node:24-slim`, `npm ci --ignore-scripts`; read-only root, all capabilities dropped, 256 MB, bound to `127.0.0.1:7300`; volumes `./state` and `./blobs`. `compose.yml` pulls `ghcr.io/feyn-machines/feyn-relay:latest`, or builds this directory with `docker compose build`. |
| `.github/workflows/image.yml`, `scripts/check-version` | The image, built by a tag (see "The image"). |
| `package-lock.json` | `@byokit/relay` 0.6.0 and everything under it, at the versions of the lockfile deployed on 2026-10-11. |

## The statement

The owner's statement that this relay's domain is one of the owner's relays
(feyn-os, `docs/superpowers/specs/2026-10-22-relay-distribution-design.md`,
section 3), made on the owner's Mac with `sign-relay DOMAIN` and put in the
state directory beside `RELAY_STATE`:

| Route | Serves | Type |
| --- | --- | --- |
| `GET`, `HEAD /feyn/v1/relay` | `relay-statement.json` | `application/json` |
| `GET`, `HEAD /feyn/v1/relay.sig` | `relay-statement.json.sig` | `application/octet-stream` |

The bytes are served exactly as stored, and read again on each request: a
renewed statement needs no restart. A missing file is `404`. The relay
checks nothing; a machine checks the signature against the package key and
refuses a relay whose statement is missing, names another host or has
expired. At start the relay logs `statement: <relay> until <expires>`, or
`statement: missing, machines will refuse this relay`.

## Machines

A machine joins the relay by its domain (`sudo feyn relay join DOMAIN` on
the machine); the operator approves it on the admin page by its code; its
people's connectors are then enrolled without the owner token (feyn-os,
relay distribution design, section 4). A machine has an Ed25519 key of its
own; its id is the base64url of SHA-256 of the raw public key, cut to 22
characters.

| Route | Does |
| --- | --- |
| `POST /feyn/v1/join` | `{name, key, details}` (at most 4 KB): `201 {id, code, expires_in: 3600}`; the same key while it waits, `200 {id, code, again: true}`; an approved machine, `200 {id, state: "approved"}`; `400` a bad body; `429` past 10 requests from one address in an hour, or 50 waiting in all |
| `GET /feyn/v1/join/<id>` | `{state}`: `waiting`, `approved`, `refused` or `expired` (an hour); a refused or expired request is answered once more, then forgotten; `404` unknown |
| `DELETE /feyn/v1/join/<id>` | signed, purpose `withdraw`: `204` |
| `POST /feyn/v1/machines/<id>/enrolments` | signed, purpose `enrol`, `{name}` the person: `201 {ticket, expires}`, a byokit enrolment named `<machine>/<person>` with `meta: {machine, person}`, five minutes |
| `POST /feyn/v1/machines/<id>/leave` | signed, purpose `leave`: every byokit host whose `meta.machine` is the machine is revoked, the machine is dropped; `204` |

A signed body carries `at` (milliseconds since the epoch) and `sig`, the
base64url Ed25519 signature over the UTF-8 of
`feyn-relay\n<purpose>\n<machine id>\n<field>\n<at>`, where `<field>` is
the person's name for `enrol` and empty otherwise. It is refused (`403`)
when the signature fails, the machine is not approved, or `at` is more than
five minutes from the relay's clock. The code is eight characters from
`ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, random, unique among waiting requests,
shown `XXXX-XXXX` on the admin page.

`machines.json` (mode `0600`, written to a temporary file and renamed)
holds the approved machines and the requests not yet answered for the last
time. Like byokit's state, it is never restored from an old copy: that
would bring back a machine that was removed.

## The admin page

`https://<RELAY_HOST>/admin`, server-rendered, one account. It shows
**Requests** (name, code as `XXXX-XXXX`, details, address, time; Approve,
Refuse), **Machines** (name, people as byokit hosts with online state and
device count, joined; Remove, which revokes every host of the machine),
**Other hosts** (byokit hosts that are no machine's, such as those enrolled
by hand with the owner token; Remove) and **Account** (change the password,
sign out).

- At first start, with no `admin.json` in the state directory, the account
  is made from `ADMIN_USER` and `ADMIN_PASSWORD` (at least 12 characters)
  and the relay logs `admin: account <name> set up`. Without them it does
  not start. Once `admin.json` exists the two are not read again: a later
  change of `.env` does not replace a password changed on the page, and the
  password may be removed from `.env`.
- The password is kept as scrypt with its salt in `admin.json` (`0600`).
  A session is a random cookie (`HttpOnly; Secure; SameSite=Strict;
  Path=/admin`, 12 hours) kept in memory; a restart signs the operator out.
  Ten wrong sign-ins within 15 minutes lock sign-in for 15 minutes.
- Every `POST` must carry `Origin: https://<RELAY_HOST>`, and every one but
  sign-in and reset the session cookie; otherwise `403`.
- A forgotten password: on the relay's server,
  `docker compose exec relay node admin.mjs reset-password` prints
  `https://<RELAY_HOST>/admin/reset#<token>`, good once within 15 minutes,
  where a new password (and, if wanted, a new name) is set. Only a hash of
  the token is kept. A reset signs every session out.

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
| `RELAY_OWNER_TOKEN` | the bearer token of the owner routes (in `.env`); used by nobody since machines join by themselves | required |
| `RELAY_HOST` | this relay's domain, for the admin page's `Origin` check and reset link | required |
| `ADMIN_USER`, `ADMIN_PASSWORD` | the admin account, read only while there is no `admin.json` | required at first start |
| `RELAY_PORT`, `LISTEN_HOST` | where to listen | `7300`, `127.0.0.1` |
| `TRUST_PROXY` | `1` to take the client address from the proxy: `cf-connecting-ip`, else the last `X-Forwarded-For` value (the first is the client's own word) | off |
| `BLOB_DIR` | where blobs are kept; unset, there are no blob routes and the relay runs as before | unset |
| `BLOB_KEY` | the endpoint's key file | `blob-key.json` beside `RELAY_STATE` |

A request may take up to 30 minutes to arrive whole (Node's default is
five), so that 51 MiB can come from a phone.

## The image

A tag `v<version>` runs `.github/workflows/image.yml`: `npm ci`, `npm test`,
`scripts/check-version` (the tag must be `v` and `package.json`'s version),
a refusal if `ghcr.io/feyn-machines/feyn-relay:<version>` exists already,
then a build of the `Dockerfile` pushed as `:<version>` and `:latest` with
the workflow's own `GITHUB_TOKEN`. To release: bump `package.json`, commit,
push `main`, then push the tag. ghcr.io makes a new package private: after
the first push the owner sets `feyn-relay`'s visibility to public once, in
the organisation's package settings; from then on a server pulls it with no
token.

## Deploying a relay

A server keeps one directory (`~/feyn-relay` on the owner's server) with
`compose.yml` from this repository, `.env` (mode `0600`) and the volumes
`state/` and `blobs/`, both owned by the container's user (`node`, uid
1000).

For a new relay, the owner:

1. Points a domain at the server (the Cloudflare tunnel today), to
   `127.0.0.1:7300`.
2. On the Mac, where the package key is, runs `sign-relay DOMAIN` (in
   `~/projects/feyn-machine/feyn-pkg`, outside git), and copies
   `relay-statement.json` and `relay-statement.json.sig` into `state/`.
   Without them every machine refuses the relay. A statement is renewed the
   same way before it expires; no restart is needed.
3. Adds `https://DOMAIN/oauth/google/callback` to the Google app's
   authorised redirect URIs: a Google sign-in comes back only to the relay
   its machine uses.
4. Writes `.env`:

   ```
   RELAY_OWNER_TOKEN=<random, kept; used by nobody>
   RELAY_HOST=DOMAIN
   ADMIN_USER=<name>
   ADMIN_PASSWORD=<at least 12 characters>
   ```

5. `docker compose pull && docker compose up -d`; the log shows
   `statement: DOMAIN until <date>` and `admin: account <name> set up`.
   `ADMIN_PASSWORD` may then be removed from `.env`.
6. Signs in at `https://DOMAIN/admin`. A machine joins with
   `sudo feyn relay join DOMAIN` and is approved there by its code.

Updating is `docker compose pull && docker compose up -d`. `state/` carries
over. An old copy of `state/` is never restored: it would bring back hosts
and machines that were removed.

The relay running on the owner's server since 2026-10-11 keeps its `.env`
and `state/`; it gains `RELAY_HOST`, `ADMIN_USER`, `ADMIN_PASSWORD`, the two
statement files and a `blobs/` directory, and `compose.yml` is replaced.
Check afterwards: `curl -s http://127.0.0.1:7300/feyn/v1/blobs/key` and
`/feyn/v1/relay` on the server and through the tunnel; the hosts enrolled by
hand are listed under "Other hosts", online; `state/blob-key.json`,
`admin.json` and `machines.json` have mode `0600`. Then, from the
experiment host, upload 51 MiB with a token made there and fetch it once
(the client plan's step J1): the check of the tunnel's body limit.

Losing `state/blob-key.json` is harmless: a new key pair is made, and
connectors read the new public key within ten minutes, or at once when an
upload of their own is refused. Removing `blobs/` loses only files nobody
had fetched yet; the sender uploads again.

## Untested until the server

- The container: the `./blobs` volume's ownership, the read-only root with
  two writable volumes, memory under a 51 MiB stream.
- The Cloudflare tunnel with a 51 MiB request body and a slow upload.
- A browser's preflight and `PUT` from the app's origin through the tunnel.
