import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,mkdirSync,mkdtempSync,readFileSync,rmSync,
  symlinkSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {
  buildProtectedBootstrapPack,verifyProtectedBootstrapPack,
  PROTECTED_BOOTSTRAP_FILES
} from '../scripts/protected-update-bootstrap-pack.mjs';

const denied=fn=>assert.throws(fn,/protected_bootstrap_pack_denied/);
function git(cwd,args){
  const result=spawnSync('git',args,{cwd,encoding:'utf8'});
  assert.equal(result.status,0,'synthetic git fixture failed');
  return result.stdout.trim();
}
function fixture(t){
  const top=mkdtempSync(join(tmpdir(),'bootstrap-pack-test-'));
  t.after(()=>rmSync(top,{recursive:true,force:true}));
  const source=join(top,'repo');
  mkdirSync(source);
  git(source,['init','-q']);
  git(source,['config','user.name','Synthetic Fixture']);
  git(source,['config','user.email','fixture@example.invalid']);
  for(const [i,path] of PROTECTED_BOOTSTRAP_FILES.entries()){
    const target=join(source,path);
    mkdirSync(dirname(target),{recursive:true});
    writeFileSync(target,'// synthetic package source '+i+'\n', {mode:0o644});
  }
  git(source,['add','.']);
  git(source,['-c','commit.gpgsign=false','commit','-qm','synthetic fixture']);
  const head=git(source,['rev-parse','HEAD']);
  return {top,source,head,out:name=>join(top,name)};
}
function build(f,name){
  return buildProtectedBootstrapPack({
    repositoryPath:f.source,head:f.head,outputPath:f.out(name)
  });
}
test('three separate reproducible package builds have one immutable fingerprint',t=>{
  const f=fixture(t);
  const bundles=['a','b','c'].map(name=>build(f,name));
  assert.equal(new Set(bundles.map(b=>b.manifestSha256)).size,1);
  assert.equal(bundles[0].fileCount,PROTECTED_BOOTSTRAP_FILES.length);
  assert.equal(bundles[0].status,'source_only_unprivileged_no_go');
  for(const name of ['a','b','c']){
    const result=verifyProtectedBootstrapPack({
      outputPath:f.out(name),expectedManifestSha256:bundles[0].manifestSha256
    });
    assert.equal(result.head,f.head);
    assert.equal(result.fileCount,PROTECTED_BOOTSTRAP_FILES.length);
  }
});
test('reject reused package output; never clobber existing data',t=>{
  const f=fixture(t);
  build(f,'a');
  denied(()=>build(f,'a'));
});
test('reject uncommitted and staged modifications to source tree',t=>{
  const f=fixture(t);
  const changed=join(f.source,PROTECTED_BOOTSTRAP_FILES[0]);
  writeFileSync(changed,'changed');
  denied(()=>build(f,'a'));
  git(f.source,['add','.']);
  denied(()=>build(f,'a'));
});
test('reject wrong commit or malformed source path before creating output',t=>{
  const f=fixture(t);
  denied(()=>buildProtectedBootstrapPack({
    repositoryPath:f.source,head:'f'.repeat(40),outputPath:f.out('a')
  }));
  denied(()=>buildProtectedBootstrapPack({
    repositoryPath:f.source,head:'../bad',outputPath:f.out('b')
  }));
});
test('verify requires independently pinned manifest digest',t=>{
  const f=fixture(t);
  const b=build(f,'a');
  denied(()=>verifyProtectedBootstrapPack({outputPath:f.out('a')}));
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:'f'.repeat(64)
  }));
  assert.equal(verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }).head,f.head);
});
test('tampering one packed file fails validation',t=>{
  const f=fixture(t),b=build(f,'a');
  const path=join(f.out('a'),'code',PROTECTED_BOOTSTRAP_FILES[0]);
  chmodSync(path,0o600);
  writeFileSync(path,'malicious synthetic change');
  chmodSync(path,0o444);
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }));
});
test('world-write or executable package source fails closed',t=>{
  const f=fixture(t),b=build(f,'a');
  const path=join(f.out('a'),'code',PROTECTED_BOOTSTRAP_FILES[0]);
  chmodSync(path,0o755);
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }));
});
test('unexpected file anywhere in bundle fails closed',t=>{
  const f=fixture(t),b=build(f,'a');
  writeFileSync(join(f.out('a'),'code','extra'),'x');
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }));
});
test('replacing source with symlink cannot be verified',t=>{
  const f=fixture(t),b=build(f,'a');
  const path=join(f.out('a'),'code',PROTECTED_BOOTSTRAP_FILES[0]);
  rmSync(path);
  symlinkSync('no-such-target',path);
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }));
});
test('extra key, tampered canonical manifest or fake install status fails',t=>{
  const f=fixture(t),b=build(f,'a');
  const path=join(f.out('a'),'MANIFEST.json');
  const original=JSON.parse(readFileSync(path,'utf8'));
  chmodSync(path,0o600);
  writeFileSync(path,JSON.stringify({...original,installAuthorized:true}));
  chmodSync(path,0o444);
  denied(()=>verifyProtectedBootstrapPack({
    outputPath:f.out('a'),expectedManifestSha256:b.manifestSha256
  }));
});
test('unsafe ancestor or non-canonical output path is refused',t=>{
  const f=fixture(t);
  denied(()=>buildProtectedBootstrapPack({
    repositoryPath:f.source,head:f.head,
    outputPath:join(f.top,'..','noncanonical')
  }));
});
