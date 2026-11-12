import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,mkdirSync,mkdtempSync,readFileSync,readdirSync,rmSync,writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join} from 'node:path';
import {
  buildProtectedBootstrapPack,verifyProtectedBootstrapPack,
  PROTECTED_BOOTSTRAP_FILES
} from '../scripts/protected-update-bootstrap-pack.mjs';
import {
  migrateProtectedOriginalPairCandidate,restoreOriginalControllerCandidate
} from '../src/ops/protected-update-bootstrap-migration.mjs';

const fail=()=>{throw Error('synthetic_git_command_failed');};
function git(path,args){
  const r=spawnSync('git',args,{cwd:path,encoding:'utf8',timeout:10000});
  if(r.status!==0||r.error)fail();
  return r.stdout.trim();
}
const hash=b=>createHash('sha256').update(b).digest('hex');
const oldPaths={
  'ai-github-canary-policy.mjs':'src/jobs/ai-github-canary-policy.mjs',
  'ai-github-canary.mjs':'scripts/ai-github-canary.mjs'
};
test('three serial fully isolated package -> baseline -> install -> restore dry runs',t=>{
  const top=mkdtempSync(join(tmpdir(),'bootstrap-e2e-'));
  t.after(()=>rmSync(top,{recursive:true,force:true}));
  const repo=join(top,'source');mkdirSync(repo);
  git(repo,['init','-q']);
  git(repo,['config','user.name','Synthetic Fixture']);
  git(repo,['config','user.email','fixture@example.invalid']);
  const original={};
  for(const [name,path] of Object.entries(oldPaths)){
    const bytes=Buffer.from('// immutable synthetic baseline '+name+'\n');
    original[name]=bytes;
    const target=join(repo,path);
    mkdirSync(dirname(target),{recursive:true});
    writeFileSync(target,bytes);
  }
  for(const [i,path] of PROTECTED_BOOTSTRAP_FILES.entries()){
    const target=join(repo,path);
    mkdirSync(dirname(target),{recursive:true});
    writeFileSync(target,'// synthetic reviewed source '+i+'\n');
  }
  git(repo,['add','.']);
  git(repo,['-c','commit.gpgsign=false','commit','-qm','synthetic reviewed sources']);
  const head=git(repo,['rev-parse','HEAD']);
  const fingerprints=[];
  for(let i=0;i<3;i++){
    const outputPath=join(top,'private-package-'+i);
    const built=buildProtectedBootstrapPack({repositoryPath:repo,head,outputPath});
    fingerprints.push(built.manifestSha256);
    const verified=verifyProtectedBootstrapPack({
      outputPath,expectedManifestSha256:built.manifestSha256
    });
    assert.equal(verified.status,'source_only_unprivileged_no_go');
    const root=join(top,'synthetic-root-'+i);
    mkdirSync(root,{mode:0o755});chmodSync(root,0o755);
    const expectedLegacyFiles=[];
    for(const [name,bytes] of Object.entries(original)){
      writeFileSync(join(root,name),bytes,{mode:0o555});
      chmodSync(join(root,name),0o555);
      const sourceBlob=spawnSync('git',['show',head+':'+oldPaths[name]],{
        cwd:repo,encoding:null,timeout:10000
      });
      assert.equal(sourceBlob.status,0);
      assert.deepEqual(sourceBlob.stdout,bytes);
      expectedLegacyFiles.push({name,bytes:bytes.length,sha256:hash(bytes)});
    }
    const wrapperBytes=readFileSync(join(outputPath,'code','scripts',
      'protected-update-controller-wrapper.mjs'));
    const wrapperSha256=hash(wrapperBytes);
    const migrated=migrateProtectedOriginalPairCandidate({
      root,baselineCommit:head,
      expectedLegacyFiles,wrapperBytes,wrapperSha256
    });
    assert.equal(migrated.phase,'migrated_pending_live_health');
    assert.equal(migrated.safeToRetry,false);
    assert.deepEqual(readFileSync(join(root,'.bootstrap-original',
      'ai-github-canary.mjs')),original['ai-github-canary.mjs']);
    assert.deepEqual(readFileSync(join(root,'ai-github-canary.mjs')),
      wrapperBytes);
    const restored=restoreOriginalControllerCandidate({
      root,baselineCommit:head,originalHashes:migrated.originalHashes,
      expectedWrapperSha256:wrapperSha256
    });
    assert.equal(restored.phase,'original_controller_restored');
    for(const [name,bytes] of Object.entries(original))
      assert.deepEqual(readFileSync(join(root,name)),bytes);
    for(const entry of readdirSync(join(root,'versions')))
      chmodSync(join(root,'versions',entry),0o700);
  }
  assert.equal(new Set(fingerprints).size,1);
});
