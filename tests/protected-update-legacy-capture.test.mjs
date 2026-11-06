import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,linkSync,mkdtempSync,readFileSync,rmSync,symlinkSync,
  unlinkSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {captureLegacyProtectedPair}
  from '../src/ops/protected-update-legacy-capture.mjs';
import {RELEASE_FILES}
  from '../src/ops/protected-update-release-pointer.mjs';

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const denied=fn=>assert.throws(fn,/protected_legacy_capture_denied/);
function fixture(t){
  const root=mkdtempSync(join(tmpdir(),'protected-legacy-'));
  t.after(()=>rmSync(root,{recursive:true,force:true}));
  chmodSync(root,0o755);
  for(const [i,name] of RELEASE_FILES.entries()){
    writeFileSync(join(root,name),Buffer.from('legacy-'+i+'\n'));
    chmodSync(join(root,name),0o555);
  }
  return root;
}

test('capture exact legacy pair bytes/hash without modifying originals',t=>{
  const root=fixture(t);
  const before=RELEASE_FILES.map(name=>readFileSync(join(root,name)));
  const result=captureLegacyProtectedPair(root);
  assert.deepEqual(result.files.map(x=>x.name),RELEASE_FILES);
  for(const [i,name] of RELEASE_FILES.entries()){
    assert.equal(result.files[i].bytes,before[i].length);
    assert.equal(result.files[i].sha256,sha256(before[i]));
    assert.deepEqual(result.contents[name],before[i]);
    assert.deepEqual(readFileSync(join(root,name)),before[i]);
  }
  assert.equal(Object.isFrozen(result),true);
  assert.equal(Object.isFrozen(result.files),true);
});

test('reject noncanonical root and symlinked root',t=>{
  const root=fixture(t);
  denied(()=>captureLegacyProtectedPair(root+'/../'+root.split('/').at(-1)));
  const alias=root+'-alias';
  symlinkSync(root,alias);
  t.after(()=>rmSync(alias,{force:true}));
  denied(()=>captureLegacyProtectedPair(alias));
});

test('reject a writable, nonexecutable or symlinked legacy member',t=>{
  const root=fixture(t),path=join(root,RELEASE_FILES[0]);
  chmodSync(path,0o755);
  denied(()=>captureLegacyProtectedPair(root));
  chmodSync(path,0o444);
  denied(()=>captureLegacyProtectedPair(root));
  unlinkSync(path);
  symlinkSync(join(root,RELEASE_FILES[1]),path);
  denied(()=>captureLegacyProtectedPair(root));
});

test('reject hardlinks and oversize legacy source',t=>{
  const root=fixture(t),path=join(root,RELEASE_FILES[0]);
  linkSync(path,join(root,'other-link'));
  denied(()=>captureLegacyProtectedPair(root));
  unlinkSync(join(root,'other-link'));
  chmodSync(path,0o644);
  writeFileSync(path,Buffer.alloc(256*1024+1,65));
  chmodSync(path,0o555);
  denied(()=>captureLegacyProtectedPair(root));
});

test('reject a legacy FIFO without blocking the reader',t=>{
  const root=fixture(t),path=join(root,RELEASE_FILES[0]);
  unlinkSync(path);
  const r=spawnSync('mkfifo',[path],{timeout:3000});
  if(r.error){t.skip('mkfifo unavailable');return;}
  assert.equal(r.status,0);
  denied(()=>captureLegacyProtectedPair(root));
});

test('reject a writable containing directory',t=>{
  const root=fixture(t);
  chmodSync(root,0o777);
  denied(()=>captureLegacyProtectedPair(root));
});
