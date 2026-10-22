// The client's address, for the limits of the join routes and the admin
// page. Behind a proxy (TRUST_PROXY=1; Cloudflare's tunnel here) the first
// X-Forwarded-For value is whatever the client wrote; the proxy's own word is
// `cf-connecting-ip`, or else the last value, which the proxy appended. Without
// TRUST_PROXY the headers are ignored and the socket's address is taken.
export function clientAddress(req, trustProxy) {
  if (trustProxy) {
    const cf = String(req.headers['cf-connecting-ip'] ?? '').trim();
    if (cf) return cf;
    const last = String(req.headers['x-forwarded-for'] ?? '').split(',').at(-1).trim();
    if (last) return last;
  }
  return req.socket?.remoteAddress ?? '';
}
