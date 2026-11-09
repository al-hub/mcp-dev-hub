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

import {createHash} from 'node:crypto';
const SHA=s=>createHash('sha256').update(s).digest('hex');
const ALL=[
 'approved-routine-context.json','codex-review.json','codex-review.sig',
 'codex-reviewer-public.pem','reviewer-public.pem','dispatch.intent.json',
 'routine-review-handoff.json','routine-approval.json',
 'routine-approval.sig','approved-request.json','issuance-complete.json'
];
function complete(){
 const h='a'.repeat(40),b='b'.repeat(40),operationId=ID;
 const manifestJson=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',commit:h,bundle:'controller-pair',
  files:[{name:'ai-github-canary-policy.mjs',sha256:'1'.repeat(64),bytes:11},
   {name:'ai-github-canary.mjs',sha256:'2'.repeat(64),bytes:22}]});
 const contextRaw=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
  head:h,base:b,prNumber:39,ciRunId:11,
  reviewerBotId:23,reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
  operationId,manifestJson,packDigest:'3'.repeat(64)});
 const fakeSignature='A'.repeat(86)+'==';
 const requestRaw=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',prNumber:39,
  head:h,base:b,ciRunId:11,operationId,manifestJson,
  approvalJson:'{}',approvalSignatureBase64:fakeSignature,
  reviewJson:'{}',reviewSignatureBase64:fakeSignature,
  routineReviewJson:'{}',routineReviewSignatureBase64:fakeSignature});
 const completionRaw=JSON.stringify({
  version:1,operationId,requestSha256:SHA(requestRaw),
  phase:'both_signed_pending_root_apply',safeToReplay:false
 });
 return {operationId,files:ALL,contextRaw,requestRaw,completionRaw};
}
test('complete canonical artifacts are identified but NEVER authenticated as PASS',()=>{
 const proof=classifyRoutineIssuerArtifacts(complete());
 assert.equal(proof.state,'issued_pending_or_unknown_apply');
 assert.equal(proof.safeToReplay,false);
 assert.equal(proof.requiresReconciliation,true);
});
test('tampered issuance receipt, mismatched operation and missing file reject',()=>{
 const f=complete();
 for(const patch of [
  {completionRaw:f.completionRaw.replace('"safeToReplay":false','"safeToReplay":true')},
  {completionRaw:f.completionRaw.replace(SHA(f.requestRaw),'f'.repeat(64))},
  {requestRaw:f.requestRaw.replace('"ciRunId":11','"ciRunId":12')},
  {files:f.files.filter(x=>x!=='routine-approval.sig')}
 ])assert.throws(()=>classifyRoutineIssuerArtifacts({...f,...patch}));
});
