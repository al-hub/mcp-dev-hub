import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateConfig, resolveWorkspace } from '../src/config.ts';

const target = () => ({ id: 'local', kind: 'local', enabled: true, workspaces: [{ id: 'demo', root: '/tmp/demo' }] });
test('synthetic example is valid but all execution targets are disabled', () => {
  const config = validateConfig(JSON.parse(readFileSync(new URL('../config/hub.example.json', import.meta.url), 'utf8')));
  assert.ok(config.targets.every(item => !item.enabled));
  assert.throws(() => resolveWorkspace(config, 'local', 'demo'), /unavailable/);
});
test('target and workspace selection must be explicit and authorized', () => {
  const config = validateConfig({ version: 1, targets: [target()] });
  assert.equal(resolveWorkspace(config, 'local', 'demo').root, '/tmp/demo');
  assert.throws(() => resolveWorkspace(config, 'remote', 'demo'), /unavailable/);
  assert.throws(() => resolveWorkspace(config, 'local', 'other'), /unavailable/);
});
test('reject malformed, duplicate, placeholder and relative runtime configuration', () => {
  for (const config of [null, {}, { version: 2, targets: [] },
    { version: 1, targets: [target(), target()] },
    { version: 1, targets: [{ ...target(), kind: 'other' }] },
    { version: 1, targets: [{ ...target(), workspaces: [{ id: 'demo', root: '../escape' }] }] },
    { version: 1, targets: [{ ...target(), workspaces: [{ id: 'demo', root: '<PATH>' }] }] },
    { version: 1, targets: [{ ...target(), kind: 'ssh', sshAlias: '-unsafe' }] },
    { version: 1, targets: [{ ...target(), workspaces: [] }] }
  ]) assert.throws(() => validateConfig(config));
});
test('validation errors do not echo private supplied values', () => {
  assert.throws(() => validateConfig({ version: 1, targets: [{ id: 'sensitive value' }] }),
    error => error instanceof Error && !error.message.includes('sensitive value'));
});
