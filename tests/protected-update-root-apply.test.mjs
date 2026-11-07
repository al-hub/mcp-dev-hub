import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {applyOneProtectedUpdateFixedRoot}
  from '../scripts/protected-update-root-apply.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const source=fileURLToPath(new URL('../scripts/protected-update-root-apply.mjs',
  import.meta.url));
test('root updater is included in immutable source pack',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-root-apply.mjs'));
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'src/ops/protected-update-health-probe.mjs'));
});
test('nonroot caller never enters privileged operation or reads stdin',async()=>{
  await assert.rejects(applyOneProtectedUpdateFixedRoot(),
    /protected_root_apply_denied/);
});
test('direct source-checkout invocation is rejected without hanging on stdin',()=>{
  const r=spawnSync(process.execPath,[source],{
    encoding:'utf8',input:'',timeout:5000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,/protected_root_apply_denied_or_unknown/);
  assert.equal(r.stdout,'');
});
test('root update command rejects all caller supplied CLI arguments',()=>{
  const r=spawnSync(process.execPath,[source,'--root','/tmp'],{
    encoding:'utf8',input:'{}',timeout:5000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,/protected_root_apply_denied_or_unknown/);
});
