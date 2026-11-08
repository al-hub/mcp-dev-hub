import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {validatePinnedOriginalHashes,restoreProtectedOriginalFixedRoot}
  from '../scripts/protected-update-bootstrap-restore.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const DENIED=/protected_bootstrap_restore_denied/;
const original=()=>[
  {name:'ai-github-canary-policy.mjs',bytes:12,sha256:'a'.repeat(64)},
  {name:'ai-github-canary.mjs',bytes:13,sha256:'b'.repeat(64)}
];
test('emergency restoration is in reviewed source pack but NOT routine sudo list',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-bootstrap-restore.mjs'));
});
test('immutable baseline manifest binds precisely both protected file hashes',()=>{
  const result=validatePinnedOriginalHashes(JSON.stringify(original()));
  assert.equal(result['ai-github-canary-policy.mjs'],'a'.repeat(64));
  assert.equal(result['ai-github-canary.mjs'],'b'.repeat(64));
  assert.ok(Object.isFrozen(result));
});
test('uncanonical and poisoned baseline manifests refuse restore',()=>{
  for(const bad of [
    '', '[]',JSON.stringify(original())+' ',
    JSON.stringify(original().slice(0,1)),
    JSON.stringify([...original(),...original()]),
    JSON.stringify(original().reverse()),
    JSON.stringify([{...original()[0],sha256:'f'},original()[1]]),
    JSON.stringify([{...original()[0],name:'../outside'},original()[1]]),
    JSON.stringify([{...original()[0],bytes:0},original()[1]]),
    JSON.stringify([{...original()[0],extra:'x'},original()[1]])
  ])assert.throws(()=>validatePinnedOriginalHashes(bad),DENIED);
});
test('non-root Worker cannot restore any protected OS source',async()=>{
  await assert.rejects(restoreProtectedOriginalFixedRoot(),DENIED);
});
test('calling emergency entry from checkout never succeeds or touches root',()=>{
  const src=fileURLToPath(new URL(
    '../scripts/protected-update-bootstrap-restore.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[src],{
    encoding:'utf8',input:'',timeout:5000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,DENIED);
  assert.equal(r.stdout,'');
});
