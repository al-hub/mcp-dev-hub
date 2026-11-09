import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyRoutineIssuerArtifacts,inspectFixedRoutineIssuerOperation}
 from '../src/ops/protected-update-routine-reconcile.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const ID='c'.repeat(32);
test('partial or empty signer slot is UNKNOWN, never a replay permit',()=>{
 for(const files of [[],['approved-routine-context.json'],
  ['dispatch.intent.json','codex-review.json'],
  ['issuance-complete.json']]){
  if(files.includes('issuance-complete.json')){
   assert.throws(()=>classifyRoutineIssuerArtifacts({
    operationId:ID,files
   }));
  }else{
   const r=classifyRoutineIssuerArtifacts({operationId:ID,files});
   assert.equal(r.state,'issuance_unknown');
   assert.equal(r.safeToReplay,false);
  }
 }
});
test('path injection, unknown artifacts and duplicate files reject',()=>{
 for(const bad of [
  {operationId:'../'+ID.slice(3),files:[]},
  {operationId:ID,files:['../../private-key']},
  {operationId:ID,files:['dispatch.intent.json','dispatch.intent.json']}
 ])assert.throws(()=>classifyRoutineIssuerArtifacts(bad));
});
test('no root read access from ordinary checkout and fixed root entrypoint',()=>{
 assert.throws(()=>inspectFixedRoutineIssuerOperation(ID));
 const script=fileURLToPath(new URL('../scripts/protected-update-root-reconcile.mjs',import.meta.url));
 const r=spawnSync(process.execPath,[script],{
  input:ID,encoding:'utf8',timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,1);
 assert.equal(r.stdout,'');
});
test('static immutable source pack includes reconciliation module',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
  'src/ops/protected-update-routine-reconcile.mjs'));
});
