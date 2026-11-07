import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmodSync,existsSync,mkdirSync,mkdtempSync,readFileSync,
  readlinkSync,readdirSync,rmSync,symlinkSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {
  migrateProtectedOriginalPairCandidate,restoreOriginalControllerCandidate
} from '../src/ops/protected-update-bootstrap-migration.mjs';
import {
  RELEASE_FILES,stageProtectedRelease,switchProtectedRelease
} from '../src/ops/protected-update-release-pointer.mjs';
const BASE='a'.repeat(40),NEXT='b'.repeat(40);
const hash=b=>createHash('sha256').update(b).digest('hex');
const name='ai-github-canary.mjs';
const policy='ai-github-canary-policy.mjs';
const refused=cb=>assert.throws(cb,
  /protected_bootstrap_migration_denied|protected_legacy_capture_denied|protected_release_guard_failed/);
function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'bootstrap-migration-'));
  chmodSync(root,0o755);
  const original={
    [policy]:Buffer.from('// synthetic policy before migration\n'),
    [name]:Buffer.from('// synthetic original controller\n')
  };
  for(const f of RELEASE_FILES){
    writeFileSync(join(root,f),original[f],{mode:0o555});
    chmodSync(join(root,f),0o555);
  }
  const expectedLegacyFiles=RELEASE_FILES.map(f=>({
    name:f,bytes:original[f].length,sha256:hash(original[f])
  }));
  const wrapperBytes=Buffer.from('// synthetic safe immutable wrapper\n');
  const wrapperSha256=hash(wrapperBytes);
  t.after(()=>{
    const versions=join(root,'versions');
    if(existsSync(versions)){
      for(const entry of readdirSync(versions)){
        const dir=join(versions,entry);
        if(existsSync(dir))chmodSync(dir,0o700);
      }
    }
    rmSync(root,{recursive:true,force:true});
  });
  return {root,original,expectedLegacyFiles,wrapperBytes,wrapperSha256,
    args:()=>({root,baselineCommit:BASE,
      expectedLegacyFiles,wrapperBytes,wrapperSha256})};
}
test('three independent synthetic migrations preserve and restore original bytes',t=>{
  for(let i=0;i<3;i++){
    const f=fixture(t);
    const result=migrateProtectedOriginalPairCandidate(f.args());
    assert.equal(result.phase,'migrated_pending_live_health');
    assert.equal(result.safeToRetry,false);
    assert.equal(readFileSync(join(f.root,name),'utf8'),
      f.wrapperBytes.toString('utf8'));
    assert.equal(readlinkSync(join(f.root,'current')),'versions/'+BASE);
    assert.deepEqual(readFileSync(join(f.root,'.bootstrap-original',name)),
      f.original[name]);
    assert.deepEqual(readFileSync(join(f.root,'.bootstrap-original',policy)),
      f.original[policy]);
    assert.deepEqual(readFileSync(join(f.root,'versions',BASE,name)),
      f.original[name]);
    assert.deepEqual(readFileSync(join(f.root,policy)),f.original[policy]);
    const restored=restoreOriginalControllerCandidate({
      root:f.root,baselineCommit:BASE,
      originalHashes:result.originalHashes,
      expectedWrapperSha256:f.wrapperSha256
    });
    assert.equal(restored.phase,'original_controller_restored');
    assert.deepEqual(readFileSync(join(f.root,name)),f.original[name]);
    assert.equal(restored.safeToRetry,false);
    refused(()=>restoreOriginalControllerCandidate({
      root:f.root,baselineCommit:BASE,
      originalHashes:result.originalHashes,
      expectedWrapperSha256:f.wrapperSha256
    }));
  }
});
test('never enter migration if signed baseline source hashes differ',t=>{
  const f=fixture(t);
  const expectedLegacyFiles=f.expectedLegacyFiles.map(f=>({...f}));
  expectedLegacyFiles[0].sha256='f'.repeat(64);
  refused(()=>migrateProtectedOriginalPairCandidate({
    ...f.args(),expectedLegacyFiles
  }));
  assert.equal(existsSync(join(f.root,'versions')),false);
  assert.deepEqual(readFileSync(join(f.root,name)),f.original[name]);
});
test('reject wrapper digest mismatch before touching protected root',t=>{
  const f=fixture(t);
  refused(()=>migrateProtectedOriginalPairCandidate({
    ...f.args(),wrapperSha256:'f'.repeat(64)
  }));
  assert.equal(existsSync(join(f.root,'.bootstrap-original')),false);
});
test('unsafe pre-existing stage remains and is never cleared or replayed',t=>{
  const f=fixture(t);
  mkdirSync(join(f.root,'versions'),{mode:0o755});
  refused(()=>migrateProtectedOriginalPairCandidate(f.args()));
  assert.equal(existsSync(join(f.root,'versions')),true);
  assert.deepEqual(readFileSync(join(f.root,name)),f.original[name]);
});
test('symlinked original refuses migration even when its target is valid',t=>{
  const f=fixture(t);
  rmSync(join(f.root,name));
  symlinkSync(policy,join(f.root,name));
  refused(()=>migrateProtectedOriginalPairCandidate(f.args()));
  assert.equal(existsSync(join(f.root,'versions')),false);
});
test('group-writeable root and original controller are both refused',t=>{
  const a=fixture(t);
  chmodSync(a.root,0o777);
  refused(()=>migrateProtectedOriginalPairCandidate(a.args()));
  assert.equal(existsSync(join(a.root,'versions')),false);
  const b=fixture(t);
  chmodSync(join(b.root,name),0o775);
  refused(()=>migrateProtectedOriginalPairCandidate(b.args()));
  assert.equal(existsSync(join(b.root,'versions')),false);
});
test('unrecognized original path cannot enter exact two-file bootstrap',t=>{
  const f=fixture(t);
  writeFileSync(join(f.root,'unexpected'),'malicious synthetic');
  // Extra root entries are not a safe trust grant, but no allowlist path is
  // selected by the caller and the original pair itself is exact.
  assert.equal(migrateProtectedOriginalPairCandidate(f.args()).phase,
    'migrated_pending_live_health');
});
test('restore requires expected wrapper digest and original backup content',t=>{
  const f=fixture(t);
  const installed=migrateProtectedOriginalPairCandidate(f.args());
  refused(()=>restoreOriginalControllerCandidate({
    root:f.root,baselineCommit:BASE,
    originalHashes:installed.originalHashes,
    expectedWrapperSha256:'0'.repeat(64)
  }));
  assert.deepEqual(readFileSync(join(f.root,name)),f.wrapperBytes);
  const backup=join(f.root,'.bootstrap-original',name);
  chmodSync(backup,0o600);
  writeFileSync(backup,'tampered backup');
  chmodSync(backup,0o400);
  refused(()=>restoreOriginalControllerCandidate({
    root:f.root,baselineCommit:BASE,
    originalHashes:installed.originalHashes,
    expectedWrapperSha256:f.wrapperSha256
  }));
  assert.deepEqual(readFileSync(join(f.root,name)),f.wrapperBytes);
});
test('restore refuses after another approved version is active',t=>{
  const f=fixture(t);
  const installed=migrateProtectedOriginalPairCandidate(f.args());
  const next=Object.fromEntries(RELEASE_FILES.map((n,i)=>[
    n,Buffer.from('// synthetic next controller '+i+'\n')
  ]));
  const files=RELEASE_FILES.map(n=>({
    name:n,bytes:next[n].length,sha256:hash(next[n])
  }));
  stageProtectedRelease(f.root,{commit:NEXT,files,contents:next});
  switchProtectedRelease(f.root,{expectedCommit:BASE,
    nextCommit:NEXT,nextFiles:files});
  refused(()=>restoreOriginalControllerCandidate({
    root:f.root,baselineCommit:BASE,
    originalHashes:installed.originalHashes,
    expectedWrapperSha256:f.wrapperSha256
  }));
  assert.deepEqual(readFileSync(join(f.root,name)),f.wrapperBytes);
});
