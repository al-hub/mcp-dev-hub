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
const accepts=value=>validateProposedProtectedUpdate(JSON.stringify(value),{verifiedCommit:sha});
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
 assert.throws(()=>validateProposedProtectedUpdate(JSON.stringify(valid())),/trusted_commit_missing/);
 assert.throws(()=>validateProposedProtectedUpdate(JSON.stringify(valid()),{verifiedCommit:'deadbeef'}),/trusted_commit_missing/);
 assert.throws(()=>validateProposedProtectedUpdate(JSON.stringify(valid()),{verifiedCommit:'d'.repeat(40)}),/invalid_protected_update_manifest/);
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

test('a JSON text boundary rejects accessors, Proxy objects and oversized input',()=>{
 let triggered=0;
 const accessor={get version(){triggered++;throw Error('accessor executed');}};
 assert.throws(()=>validateProposedProtectedUpdate(accessor,{verifiedCommit:sha}),/invalid_update_json_input/);
 const proxy=new Proxy({}, {get(){triggered++;throw Error('proxy executed');}});
 assert.throws(()=>validateProposedProtectedUpdate(proxy,{verifiedCommit:sha}),/invalid_update_json_input/);
 assert.equal(triggered,0);
 assert.throws(()=>validateProposedProtectedUpdate('x'.repeat(4097),{verifiedCommit:sha}),/invalid_update_json_input/);
 assert.throws(()=>validateProposedProtectedUpdate('{truncated',{verifiedCommit:sha}),/invalid_update_json_input/);
 assert.throws(()=>validateProposedProtectedUpdate('null',{verifiedCommit:sha}),/invalid_protected_update_manifest/);
});
test('JSON own prototype-style metadata and extra fields are rejected',()=>{
 const obj=JSON.parse(JSON.stringify(valid()));
 obj.__proto__ = {constructor:'an attacker should not control privilege'};
 // __proto__ assignment changes a JS object prototype; the actual JSON
 // attack surface is an OWN "__proto__" key parsed from JSON text.
 const withOwnProto='{"__proto__":{"admin":true},'+JSON.stringify(valid()).slice(1);
 assert.throws(()=>validateProposedProtectedUpdate(withOwnProto,{verifiedCommit:sha}),/invalid_protected_update_manifest/);
 const constructorTag='{"constructor":"overwrite",'+JSON.stringify(valid()).slice(1);
 assert.throws(()=>validateProposedProtectedUpdate(constructorTag,{verifiedCommit:sha}),/invalid_protected_update_manifest/);
 const fileProto=JSON.parse(JSON.stringify(valid()));
 const f=JSON.stringify(fileProto.files[0]).slice(1);
 const raw=JSON.stringify({...fileProto,files:[JSON.parse('{"__proto__":true,'+f),fileProto.files[1]]});
 assert.throws(()=>validateProposedProtectedUpdate(raw,{verifiedCommit:sha}),/invalid_protected_update_file/);
});
test('exact file-size limits and JSON type boundaries',()=>{
 const v=valid();
 assert.doesNotThrow(()=>accepts({...v,files:[{...v.files[0],bytes:1},{...v.files[1],bytes:262144}]}));
 assert.throws(()=>accepts({...v,files:[{...v.files[0],bytes:262145},v.files[1]]}),/invalid_protected_update_file/);
 assert.throws(()=>accepts({...v,files:[{...v.files[0],sha256:null},v.files[1]]}),/invalid_protected_update_file/);
 assert.throws(()=>accepts({...v,files:[{...v.files[0],name:null},v.files[1]]}),/invalid_protected_update_file/);
 assert.throws(()=>accepts({...v,commit:123}),/invalid_protected_update_manifest/);
 assert.throws(()=>accepts({...v,files:[{...v.files[0],bytes:true},v.files[1]]}),/invalid_protected_update_file/);
});

test('reject duplicate JSON keys and noncanonical manifest bytes before root verification',()=>{
 const raw=JSON.stringify(valid());
 for(const candidate of [
  raw.replace('"version":1','"version":1,"version":1'),
  raw.replace('"bytes":1200','"bytes":1200,"bytes":1200'),
  raw.replace('"name":"ai-github-canary-policy.mjs"',
   '"name":"ai-github-canary-policy.mjs","name":"ai-github-canary-policy.mjs"'),
  ' '+raw,raw.replace('"files":','"files": ')
 ]){
  assert.notEqual(JSON.stringify(JSON.parse(candidate)),candidate);
  assert.throws(()=>validateProposedProtectedUpdate(candidate,{verifiedCommit:sha}),
   /noncanonical_protected_update_manifest/);
 }
});
