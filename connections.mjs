// One log line for every WebSocket the relay takes, when it closes (feyn-os
// issue #454): which side (a device or a host), the host's id cut to six
// characters, where it came in (Cloudflare's colo from cf-ray and the
// country from cf-ipcountry, when behind Cloudflare), how long it lived, its
// close code and reason as the WebSocket received them (the peer's close
// frame; 1006 when none came), and the bytes each way. No address and no payload.
//
// The close code is only on byokit's WebSocket, which `relay.upgrade` makes
// inside its own WebSocketServer (`relay.wss`, not part of its typed API;
// @byokit/relay is pinned to 0.6.0 in the lockfile and relay.test.mjs checks
// the code is read). Without it, the line has `code=?`.
const short = (id) => (id ? id.slice(0, 6) : '-');
const clean = (s) => String(s ?? '').replace(/[^\x21-\x7e ]/g, '').slice(0, 60);

export function watchConnections(relay, { log, now = Date.now } = {}) {
  const wss = relay.wss;
  const bySocket = new WeakMap();
  if (wss && typeof wss.handleUpgrade === 'function') {
    const handle = wss.handleUpgrade.bind(wss);
    wss.handleUpgrade = (req, socket, head, cb) => handle(req, socket, head, (ws) => {
      // Nothing here may stop the connection: a failure only loses the code.
      try { listen(ws, bySocket.get(socket)); } catch {}
      cb(ws);
    });
  }
  function listen(ws, c) {
    if (c && c.side === 'host') {
      // A host's id is known once byokit has registered its hello; look for
      // it on its messages and, registered before byokit's own listener, at
      // its close, while it is still in `live`.
      const find = () => { if (!c.host) try { for (const [id, l] of relay.live ?? []) if (l.ws === ws) c.host = id; } catch {} };
      ws.on('message', find);
      ws.on('close', find);
    }
    // ws emits close after the socket's own; the line is written then.
    if (c) { c.ws = true; ws.on('close', (code, reason) => { try { c.code = code; c.why = clean(reason); c.end(); } catch {} }); }
  }
  return (req, socket) => { try { watch(req, socket); } catch {} };
  function watch(req, socket) {
    const path = new URL(req.url ?? '/', 'http://relay').pathname;
    const device = /^\/link\/v1\/([A-Za-z0-9_-]{22})$/.exec(path);
    if (!device && path !== '/relay/v1/host') return;
    const ray = String(req.headers['cf-ray'] ?? '');
    const c = {
      side: device ? 'device' : 'host',
      host: device?.[1],
      colo: clean(/-([A-Z]{3})$/.exec(ray)?.[1] ?? '-'),
      country: clean(req.headers['cf-ipcountry'] ?? '-'),
      at: now(),
    };
    bySocket.set(socket, c);
    let done = false;
    c.end = () => {
      if (done) return;
      done = true;
      const why = c.why ? ` why="${c.why}"` : '';
      log(`ws side=${c.side} host=${short(c.host)} colo=${c.colo} country=${c.country} ms=${now() - c.at} code=${c.code ?? '?'}${why} in=${socket.bytesRead} out=${socket.bytesWritten}`);
    };
    // A socket byokit never made a WebSocket of is written when it closes.
    socket.once('close', () => { try { if (!c.ws) c.end(); } catch {} });
  }
}
