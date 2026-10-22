// The image workflow's first step: a tag builds only the version that
// package.json names (relay distribution design, section 6.1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const script = join(import.meta.dirname, 'check-version');
const { version } = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'package.json'), 'utf8'));
const run = (...args) => spawnSync(script, args, { encoding: 'utf8' });

test('the tag v<package.json version> passes and prints the version', () => {
  const r = run(`v${version}`);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout, `${version}\n`);
  // As the workflow runs it: a relative path from the repository's root.
  const rel = spawnSync('scripts/check-version', [`v${version}`], { cwd: join(import.meta.dirname, '..'), encoding: 'utf8' });
  assert.equal(rel.status, 0, rel.stderr);
});

test('any other tag is refused before building', () => {
  for (const tag of [version, `v${version}.1`, `v${version}-rc`, 'v0.0.0', `refs/tags/v${version}`, '']) {
    const r = run(tag);
    assert.notEqual(r.status, 0, tag);
    assert.match(r.stderr, /does not match/, tag);
  }
  assert.notEqual(run().status, 0);
});
