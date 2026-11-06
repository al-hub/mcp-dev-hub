import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readlinkSync, readdirSync, rmSync, symlinkSync, statSync, writeFileSync
} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {
  RELEASE_FILES,inspectProtectedRelease,stageProtectedRelease,
  switchProtectedRelease
} from '../src/ops/protected-update-release-pointer.mjs';

const A='a'.repeat(40),B='b'.repeat(40),C='c'.repeat(40);
const bytes=(tag)=>Object.fromEntries(
  RELEASE_FILES.map((name,i)=>[name,Buffer.from('synthetic-'+tag+'-'+i+'\n')])
);
const files=contents=>RELEASE_FILES.map(name=>({
  name,bytes:contents[name].length,sha256:createHash('sha256')
    .update(contents[name]).digest('hex')
}));
function layout(t){
  const root=mkdtempSync(join(tmpdir(),'protected-pointer-'));
  mkdirSync(join(root,'versions'),{mode:0o755});
  chmodSync(root,0o755);
  chmodSync(join(root,'versions'),0o755);
  // Release folders are intentionally read-only; restore test-fixture
  // permissions before cleanup, without touching any protected OS path.
  t.after(()=>{
    for(const name of readdirSync(join(root,'versions'))){
      const dir=join(root,'versions',name);
      if(lstatSync(dir).isDirectory())chmodSync(dir,0o700);
    }
    rmSync(root,{recursive:true,force:true});
  });
  return root;
}
const fixture=(root,sha,tag)=>{
  const contents=bytes(tag),list=files(contents);
  stageProtectedRelease(root,{commit:sha,files:list,contents});
  return list;
};
test('atomic current pointer selects exactly one immutable two-file version',t=>{
  const root=layout(t);
  const af=fixture(root,A,'A'),bf=fixture(root,B,'B');
  assert.equal(inspectProtectedRelease(root),null);
  assert.deepEqual(switchProtectedRelease(root,{
    expectedCommit:null,nextCommit:A,nextFiles:af
  }),{from:null,to:A});
  assert.equal(inspectProtectedRelease(root,{files:af}),A);
  assert.equal(readlinkSync(join(root,'current')),'versions/'+A);
  assert.deepEqual(switchProtectedRelease(root,{
    expectedCommit:A,nextCommit:B,nextFiles:bf
  }),{from:A,to:B});
  assert.equal(inspectProtectedRelease(root,{files:bf}),B);
  assert.equal(readFileSync(join(root,'versions',A,RELEASE_FILES[0]),'utf8'),
    bytes('A')[RELEASE_FILES[0]].toString());
  assert.equal(lstatSync(join(root,'current')).isSymbolicLink(),true);
});
test('explicit CAS rollback restores old release without replay',t=>{
  const root=layout(t),af=fixture(root,A,'A'),bf=fixture(root,B,'B');
  switchProtectedRelease(root,{expectedCommit:null,nextCommit:A,nextFiles:af});
  switchProtectedRelease(root,{expectedCommit:A,nextCommit:B,nextFiles:bf});
  assert.throws(()=>switchProtectedRelease(root,{
    expectedCommit:A,nextCommit:B,nextFiles:bf
  }));
  assert.deepEqual(switchProtectedRelease(root,{
    expectedCommit:B,nextCommit:A,nextFiles:af
  }),{from:B,to:A});
  assert.equal(inspectProtectedRelease(root,{files:af}),A);
});
test('stale and incorrect bytes refuse switch without altering current',t=>{
  const root=layout(t),af=fixture(root,A,'A'),bf=fixture(root,B,'B');
  switchProtectedRelease(root,{expectedCommit:null,nextCommit:A,nextFiles:af});
  assert.throws(()=>switchProtectedRelease(root,{
    expectedCommit:A,nextCommit:B,
    nextFiles:bf.map(f=>({...f,sha256:'0'.repeat(64)}))
  }));
  assert.equal(inspectProtectedRelease(root,{files:af}),A);
});
test('outside allowlist, path traversal, wrong digest and incomplete pair blocked',t=>{
  const root=layout(t),good=bytes('A');
  for(const patch of [
    {commit:'../bad'},
    {files:files(good).slice(0,1)},
    {files:[...files(good).slice(0,1),{name:'../../etc/sudoers',
      bytes:4,sha256:'1'.repeat(64)}]},
    {contents:{...good,[RELEASE_FILES[0]]:Buffer.from('tampered')}},
    {files:files(good).map(f=>({...f,sha256:'0'.repeat(64)}))}
  ]){
    const isolated=layout(t);
    assert.throws(()=>stageProtectedRelease(isolated,{
      commit:A,files:files(good),contents:good,...patch
    }));
    assert.equal(inspectProtectedRelease(isolated),null);
  }
});
test('symlinked version and corrupt file prevent activation',t=>{
  const root=layout(t),af=fixture(root,A,'A'),bf=fixture(root,B,'B');
  switchProtectedRelease(root,{expectedCommit:null,nextCommit:A,nextFiles:af});
  chmodSync(join(root,'versions',B),0o755);
  rmSync(join(root,'versions',B,RELEASE_FILES[0]));
  symlinkSync(join(root,'versions',A,RELEASE_FILES[0]),
    join(root,'versions',B,RELEASE_FILES[0]));
  assert.throws(()=>switchProtectedRelease(root,{
    expectedCommit:A,nextCommit:B,nextFiles:bf
  }));
  assert.equal(inspectProtectedRelease(root,{files:af}),A);
});
test('stale lock, left-over stage and pointer CAS fail closed',t=>{
  const root=layout(t),af=fixture(root,A,'A'),bf=fixture(root,B,'B');
  switchProtectedRelease(root,{expectedCommit:null,nextCommit:A,nextFiles:af});
  writeFileSync(join(root,'.switch.lock'),'stale',{mode:0o600});
  assert.throws(()=>switchProtectedRelease(root,{
    expectedCommit:A,nextCommit:B,nextFiles:bf
  }));
  assert.equal(readFileSync(join(root,'.switch.lock'),'utf8'),'stale');
  assert.equal(inspectProtectedRelease(root,{files:af}),A);
  const other=layout(t);
  mkdirSync(join(other,'versions','.stage-'+C),{mode:0o700});
  assert.throws(()=>stageProtectedRelease(other,{
    commit:C,files:files(bytes('C')),contents:bytes('C')
  }));
  assert.ok(existsSync(join(other,'versions','.stage-'+C)));
});

test('release bytes and directories stay Worker-readable under restrictive umask',t=>{
  const root=layout(t),contents=bytes('A'),expected=files(contents);
  const initial=process.umask(0o077);
  try {
    stageProtectedRelease(root,{commit:A,files:expected,contents});
  }finally{process.umask(initial);}
  for(const item of RELEASE_FILES){
    assert.equal(statSync(join(root,'versions',A,item)).mode&0o777,0o444);
  }
  assert.equal(statSync(join(root,'versions',A)).mode&0o777,0o555);
  assert.deepEqual(switchProtectedRelease(root,{
    expectedCommit:null,nextCommit:A,nextFiles:expected
  }),{from:null,to:A});
});
test('untraversable root or version directory fails closed',t=>{
  const root=layout(t),contents=bytes('A'),expected=files(contents);
  chmodSync(join(root,'versions'),0o700);
  assert.throws(()=>stageProtectedRelease(root,{
    commit:A,files:expected,contents
  }),/protected_release_guard_failed/);
  assert.throws(()=>inspectProtectedRelease(root),
    /protected_release_guard_failed/);
  chmodSync(join(root,'versions'),0o755);
  assert.equal(inspectProtectedRelease(root),null);
});
