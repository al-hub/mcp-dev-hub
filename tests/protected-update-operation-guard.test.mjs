import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmodSync,existsSync,mkdtempSync,readFileSync,rmSync,writeFileSync
} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {
  assertPinnedProtectedLauncher,withProtectedOperationGuard,
  markProtectedOriginalRecovery
} from '../src/ops/protected-update-operation-guard.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const denied=/protected_operation_guard_denied_or_unknown/;
function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'mcp35-operator-'));
  chmodSync(root,0o755);
  const bytes=Buffer.from('// test-only installed wrapper\\n');
  const path=join(root,'ai-github-canary.mjs');
  writeFileSync(path,bytes,{mode:0o555});
  chmodSync(path,0o555);
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  return {root,path,bytes,digest:createHash('sha256').update(bytes).digest('hex')};
}
test('fixed exclusion guard is part of the immutable reviewed source packet',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'src/ops/protected-update-operation-guard.mjs'));
});
test('actual flat launcher byte hash and file mode are mandatory',t=>{
  const f=fixture(t);
  assert.equal(assertPinnedProtectedLauncher(f.root,f.digest),true);
  assert.throws(()=>assertPinnedProtectedLauncher(f.root,'0'.repeat(64)),denied);
  chmodSync(f.path,0o644);
  writeFileSync(f.path,'// attacker changed executable\\n');
  chmodSync(f.path,0o555);
  assert.throws(()=>assertPinnedProtectedLauncher(f.root,f.digest),denied);
  assert.notEqual(readFileSync(f.path,'utf8'),f.bytes.toString('utf8'));
});
test('restoration permanently fences new updates and blocks overlapping operations',async t=>{
  const f=fixture(t);let overlapStarted=false;
  const result=await withProtectedOperationGuard(f.root,async()=>{
    await assert.rejects(withProtectedOperationGuard(f.root,async()=>{
      overlapStarted=true;return true;
    }));
    const fence=markProtectedOriginalRecovery(f.root);
    assert.equal(fence.state,'original_recovery_fenced_no_updates');
    return {phase:'restored'};
  });
  assert.equal(result.phase,'restored');
  assert.equal(overlapStarted,false);
  assert.equal(existsSync(join(f.root,'.protected-original-restored')),true);
  assert.equal(existsSync(join(f.root,'.protected-operation.lock')),false);
  await assert.rejects(withProtectedOperationGuard(f.root,async()=>true),denied);
  assert.throws(()=>assertPinnedProtectedLauncher(f.root,f.digest),denied);
});
test('UNKNOWN operation preserves exclusive lock; never silently reacquires it',async t=>{
  const f=fixture(t);
  await assert.rejects(withProtectedOperationGuard(f.root,async()=>{
    throw Error('synthetic_unknown_before_terminal');
  }),/synthetic_unknown_before_terminal/);
  assert.equal(existsSync(join(f.root,'.protected-operation.lock')),true);
  await assert.rejects(withProtectedOperationGuard(f.root,async()=>true));
  assert.equal(existsSync(join(f.root,'.protected-original-restored')),false);
});

test('confirmed pre-mutation rejection releases lock; the next safe operation can proceed',async t=>{
 for(const rejected of ['invalid-signature','unhealthy-baseline','expiry']){
  const f=fixture(t);let effectStarted=false;
  await assert.rejects(withProtectedOperationGuard(f.root,async()=>{
    effectStarted=true;return true;
  },{verifyReadOnly:()=>{
    throw Error('confirmed_read_only_'+rejected);
  }}),/confirmed_read_only_/);
  assert.equal(effectStarted,false);
  assert.equal(existsSync(join(f.root,'.protected-operation.lock')),false);
  const approved=await withProtectedOperationGuard(f.root,async()=>true,
    {verifyReadOnly:()=>true});
  assert.equal(approved,true);
 }
});
test('read-only preflight returning anything except true cannot enter mutation',async t=>{
 const f=fixture(t);let mutated=false;
 await assert.rejects(withProtectedOperationGuard(f.root,async()=>{
   mutated=true;return true;
 },{verifyReadOnly:()=>false}),denied);
 assert.equal(mutated,false);
 assert.equal(existsSync(join(f.root,'.protected-operation.lock')),false);
});
