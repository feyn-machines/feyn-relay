// The image copies its modules one by one; a module left out of the Dockerfile
// passes every other test and stops the relay starting (0.3.4 on 2026-11-09:
// ERR_MODULE_NOT_FOUND for connections.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

test('the Dockerfile copies every module the relay runs', () => {
  const dockerfile = readFileSync(new URL('./Dockerfile', import.meta.url), 'utf8');
  const copied = new Set(dockerfile.split('\n')
    .filter((line) => line.startsWith('COPY '))
    .flatMap((line) => line.split(/\s+/).slice(1, -1)));
  const modules = readdirSync(new URL('.', import.meta.url))
    .filter((name) => name.endsWith('.mjs') && !name.endsWith('.test.mjs'));
  for (const name of modules) assert.ok(copied.has(name), `${name} is not copied into the image`);
});
