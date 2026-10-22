// Where a service's OAuth sign-in comes back to (person home and connections
// design, section 6a). A person signs in to a service in the browser of their
// own device; the service then sends that browser here with a code. The
// machine that started the sign-in made a random `state` and is the only one
// that knows it; it fetches the code under that state, once, within ten
// minutes, and exchanges it itself. Nothing here can use a code: that takes
// the application's secret, which is on the machine. No account, no token and
// no secret passes through this process, and nothing is written to disk.
//
//   GET /oauth/<service>/callback?code=…&state=…     from the person's browser
//   GET /oauth/<service>/callback?error=…&state=…    the person refused, or the service did
//   GET /oauth/<service>/code?state=…                from the machine: {code} or {error}, once
export const LIMITS = {
  keepMs: 10 * 60_000,   // how long a code waits to be fetched
  max: 1000,             // codes waiting at once; the oldest goes
  codeChars: 2048,
};

// 32 random bytes in base64url, as the machine makes it.
const STATE = /^[A-Za-z0-9_-]{43}$/;
const SERVICE = /^\/oauth\/([a-z]{1,32})\/(callback|code)$/;

const page = (title, text) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;margin:18vh auto;max-width:26rem;padding:0 1.5rem;color:#222;background:#faf9f5}h1{font-size:1.25rem}</style>
</head><body><h1>${title}</h1><p>${text}</p></body></html>
`;

export function createOauth(o = {}) {
  const now = o.now ?? Date.now;
  const max = o.max ?? LIMITS.max;
  // "<service> <state>" -> { code | error, at }, oldest first.
  const kept = new Map();

  function sweep() {
    const t = now();
    for (const [k, v] of kept) { if (t - v.at >= LIMITS.keepMs) kept.delete(k); else break; }
    while (kept.size > max) kept.delete(kept.keys().next().value);
  }

  function html(res, status, title, text) {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'no-referrer' }).end(page(title, text));
  }
  function json(res, status, body) {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }).end(JSON.stringify(body));
  }

  // Answers true when the request was this module's.
  async function request(req, res) {
    const url = new URL(req.url ?? '/', 'http://relay');
    const m = SERVICE.exec(url.pathname);
    if (!m) return false;
    if (req.method !== 'GET') { json(res, 405, { error: 'method' }); return true; }
    const [, service, what] = m;
    const state = url.searchParams.get('state') ?? '';
    sweep();
    if (what === 'code') {
      const key = `${service} ${state}`;
      const v = STATE.test(state) ? kept.get(key) : undefined;
      if (!v) { json(res, 404, { error: 'not_found' }); return true; }
      kept.delete(key);
      json(res, 200, v.code !== undefined ? { code: v.code } : { error: v.error });
      return true;
    }
    const code = url.searchParams.get('code'), error = url.searchParams.get('error');
    const key = `${service} ${state}`;
    const good = STATE.test(state) && !kept.has(key) &&
      (code ? code.length <= LIMITS.codeChars : !!error && /^[a-z_]{1,100}$/.test(error));
    if (!good) {
      html(res, 400, 'This sign-in cannot be completed', 'Go back to Feyn and start the connection again.');
      return true;
    }
    kept.set(key, code ? { code, at: now() } : { error, at: now() });
    sweep();
    if (code) html(res, 200, 'Almost done', 'You can close this page and go back to Feyn. It finishes the connection there.');
    else html(res, 200, 'Not connected', 'The sign-in was not completed. You can close this page and go back to Feyn.');
    return true;
  }

  return { request, size: () => kept.size };
}
