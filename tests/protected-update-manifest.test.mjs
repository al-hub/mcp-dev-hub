import test from 'node:test';
import assert from 'node:assert/strict';
import {
 PROTECTED_REPOSITORY,validateProposedProtectedUpdate
} from '../src/ops/protected-update-manifest.mjs';

const sha='a'.repeat(40);
const digest='b'.repeat(64);
const valid=()=>({
 version:1,repository:PROTECTED_REPOSITORY,commit:sha,bundle:'controller-pair',
 files:[
  {name:'ai-github-canary-policy.mjs',sha256:digest,bytes:1200},
  {name:'ai-github-canary.mjs',sha256:'c'.repeat(64),bytes:2000}
 ]
});
const accepts=value=>validateProposedProtectedUpdate(value,{verifiedCommit:sha});
test('valid controller pair is normalized and frozen (not an authorization)',()=>{
 const got=accepts(valid());
 assert.equal(got.repository,PROTECTED_REPOSITORY);
 assert.equal(got.commit,sha);
 assert.deepEqual(got.files.map(x=>x.name),
  ['ai-github-canary-policy.mjs','ai-github-canary.mjs'].sort((a,b)=>a.localeCompare(b,'en')));
 assert.ok(Object.isFrozen(got));
 assert.ok(Object.isFrozen(got.files));
 assert.ok(got.files.every(Object.isFrozen));
});
test('manifest rejects untrusted or stale commit',()=>{
 assert.throws(()=>validateProposedProtectedUpdate(valid()),/trusted_commit_missing/);
 assert.throws(()=>validateProposedProtectedUpdate(valid(),{verifiedCommit:'deadbeef'}),/trusted_commit_missing/);
 assert.throws(()=>validateProposedProtectedUpdate(valid(),{verifiedCommit:'d'.repeat(40)}),/invalid_protected_update_manifest/);
 assert.throws(()=>accepts({...valid(),commit:'d'.repeat(40)}),/invalid_protected_update_manifest/);
});
test('manifest rejects changed repository or claimed bundle capability',()=>{
 for(const patch of [
  {repository:'another/repository'}, {repository:''},
  {version:2},{version:'1'},{bundle:'model-binaries'},
  {bundle:'controller-pair',source:'workspace'}
 ]){
  assert.throws(()=>accepts({...valid(),...patch}),/invalid_protected_update_manifest/);
 }
});
test('only the exact atomic controller pair is allowed',()=>{
 const v=valid();
 for(const files of [
  [],[v.files[0]],[v.files[0],v.files[0]],[...v.files,v.files[0]],
  [v.files[0],{...v.files[1],name:'agy'}],
  [v.files[0],{...v.files[1],name:'../../../etc/sudoers'}],
  [v.files[0],{...v.files[1],name:'/usr/local/lib/mcp-dev-hub/agy'}],
  [v.files[0],{...v.files[1],name:'ai-github-canary.mjs/other'}]
 ]){
  assert.throws(()=>accepts({...v,files}));
 }
});
test('file hashes, byte sizes and extra instructions are rejected',()=>{
 const v=valid();
 const mutations=[
  {sha256:'b'.repeat(63)},{sha256:'B'.repeat(64)},
  {sha256:'x'.repeat(64)},{sha256:''},
  {bytes:0},{bytes:-1},{bytes:1.4},{bytes:1e9},{bytes:Infinity},
  {bytes:'42'},{mode:'0777'},{source:'/tmp/candidate'},{symlink:true}
 ];
 for(const change of mutations){
  assert.throws(()=>accepts({...v,files:[{...v.files[0],...change},v.files[1]]}),
   /invalid_protected_update_file/);
 }
});
test('prototype metadata and arbitrary steps are rejected',()=>{
 const v=valid();
 assert.throws(()=>accepts({...v,commands:['sh','-c','id']}),/invalid_protected_update_manifest/);
 assert.throws(()=>accepts(null),/invalid_protected_update_manifest/);
 assert.throws(()=>accepts({...v,files:[null,v.files[1]]}),/invalid_protected_update_file/);
 assert.throws(()=>accepts({...v,files:{0:v.files[0],1:v.files[1],length:2}}),
  /invalid_protected_update_file_count/);
});
