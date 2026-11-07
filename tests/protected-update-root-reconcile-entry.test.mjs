import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {reconcileOneProtectedUpdateFixedRoot}
  from '../scripts/protected-update-root-reconcile.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const path=fileURLToPath(new URL('../scripts/protected-update-root-reconcile.mjs',
  import.meta.url));
test('source pack pins read-only recovery by immutable operation ID',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-root-reconcile.mjs'));
});
test('recovery from untrusted checkout has no root authorization',async()=>{
  await assert.rejects(reconcileOneProtectedUpdateFixedRoot(),
    /protected_root_reconcile_denied/);
});
test('direct recovery execution from checkout never reports success',()=>{
  const result=spawnSync(process.execPath,[path],{
    input:'a'.repeat(32)+'\n',encoding:'utf8',
    timeout:5000,maxBuffer:4096
  });
  assert.equal(result.status,1);
  assert.match(result.stderr,/protected_root_reconcile_denied_or_unknown/);
  assert.equal(result.stdout,'');
});
test('caller CLI flags cannot change privileged recovery roots',()=>{
  const result=spawnSync(process.execPath,[path,'--root','/tmp'],{
    input:'a'.repeat(32),encoding:'utf8',timeout:5000,maxBuffer:4096
  });
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
});
