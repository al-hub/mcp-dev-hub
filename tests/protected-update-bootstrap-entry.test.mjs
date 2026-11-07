import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  bootstrapOneShotFixedRoot
} from '../scripts/protected-update-bootstrap-entry.mjs';
import {
  PROTECTED_BOOTSTRAP_FILES
} from '../scripts/protected-update-bootstrap-pack.mjs';

const src=fileURLToPath(new URL('../scripts/protected-update-bootstrap-entry.mjs',
  import.meta.url));
test('source package includes the fixed root bootstrap entrypoint',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-bootstrap-entry.mjs'));
});
test('direct bootstrap API denies being run from untrusted checkout',()=>{
  assert.throws(()=>bootstrapOneShotFixedRoot(),
    /protected_bootstrap_entry_denied/);
});
test('direct source-script invocation returns nonzero, not false success',()=>{
  const r=spawnSync(process.execPath,[src],{
    encoding:'utf8',timeout:8000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,/protected_bootstrap_entry_denied/);
  assert.equal(r.stdout,'');
});
test('unexpected arguments cannot select root, policy or commands',()=>{
  const r=spawnSync(process.execPath,[src,'/etc','--install'],{
    encoding:'utf8',timeout:8000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,/protected_bootstrap_entry_denied/);
});
