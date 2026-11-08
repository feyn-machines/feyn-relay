// connections.mjs alone, with a fake socket: what a line says.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { watchConnections } from './connections.mjs';

const socket = () => Object.assign(new EventEmitter(), { bytesRead: 120, bytesWritten: 340 });

test('a device socket is written when it closes, with Cloudflare\'s colo and country and no address', () => {
  const lines = [];
  let t = 1000;
  const watch = watchConnections({}, { log: (l) => lines.push(l), now: () => t });
  const s = socket();
  watch({ url: `/link/v1/${'Ab'.repeat(11)}`, headers: { 'cf-ray': '8f1e2d3c4b5a6978-HKG', 'cf-ipcountry': 'CN', 'cf-connecting-ip': '203.0.113.9' } }, s);
  t = 3500;
  s.emit('close');
  assert.deepEqual(lines, ['ws side=device host=AbAbAb colo=HKG country=CN ms=2500 code=? in=120 out=340']);
});

test('a host socket without Cloudflare in front; other paths are not watched', () => {
  const lines = [];
  const watch = watchConnections({}, { log: (l) => lines.push(l), now: () => 0 });
  const h = socket();
  watch({ url: '/relay/v1/host', headers: {} }, h);
  const other = socket();
  watch({ url: '/feyn/v1/blobs/key', headers: {} }, other);
  h.emit('close');
  other.emit('close');
  assert.deepEqual(lines, ['ws side=host host=- colo=- country=- ms=0 code=? in=120 out=340']);
});
