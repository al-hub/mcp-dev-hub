import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inspectFile } from '../scripts/privacy-rules.mjs';

test('private runtime paths cannot be committed even if force-added', () => {
  for (const path of ['.env', '.env.production', 'config/actual.json', 'state/jobs.db', '.ssh/config', '.mcp.json', 'demo.local.json']) {
    assert.ok(inspectFile(path, '').includes('private-runtime-path'));
  }
});
test('detect synthetic secret and identifying candidates without reporting their content', () => {
  const candidates = [
    ['-----BEGIN ' + 'OPENSSH PRIVATE KEY-----', 'private-key'],
    ['ghp_' + 'a'.repeat(30), 'provider-token'],
    ['person' + '@' + 'private-domain.test', 'email-address'],
    [['192', '0', '2', '5'].join('.'), 'ipv4-address'],
    ['/' + 'home/' + 'synthetic-person', 'personal-absolute-path'],
    ['password' + '="' + 'synthetic-value' + '"', 'credential-assignment']
  ];
  for (const [value, category] of candidates) {
    const result = inspectFile('fixture.txt', value);
    assert.ok(result.includes(category));
    assert.ok(!JSON.stringify(result).includes(value));
  }
});
test('public placeholders and reserved example domains are allowed', () => {
  assert.deepEqual(inspectFile('config/hub.example.json', '<ABSOLUTE_WORKSPACE_PATH>'), []);
  assert.deepEqual(inspectFile('README.md', 'user@example.com host.invalid'), []);
});
