// The client's address behind the relay's proxy (Cloudflare's tunnel): what
// the proxy itself saw, never what the client wrote into a header.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { clientAddress } from './address.mjs';

const req = (headers, remoteAddress = '127.0.0.1') => ({ headers, socket: { remoteAddress } });

test('TRUST_PROXY: cf-connecting-ip first, else the last X-Forwarded-For value', () => {
  assert.equal(clientAddress(req({ 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '6.6.6.6, 198.51.100.1' }), true), '203.0.113.7');
  // The first value is whatever the client sent; the proxy appends what it saw.
  assert.equal(clientAddress(req({ 'x-forwarded-for': '6.6.6.6, 198.51.100.1' }), true), '198.51.100.1');
  assert.equal(clientAddress(req({ 'x-forwarded-for': ' 198.51.100.2 ' }), true), '198.51.100.2');
  assert.equal(clientAddress(req({ 'x-forwarded-for': '6.6.6.6, ' }), true), '127.0.0.1');
  assert.equal(clientAddress(req({}), true), '127.0.0.1');
});

test('without TRUST_PROXY the headers are ignored', () => {
  assert.equal(clientAddress(req({ 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '198.51.100.1' }), false), '127.0.0.1');
  assert.equal(clientAddress({ headers: {}, socket: {} }, false), '');
});
