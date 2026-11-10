import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {parseProtectedRoutineIntent}
  from '../src/ops/protected-update-routine-intent.mjs';
import {verifyRoutineStageInputs,stageFixedRoutineOperation}
  from '../src/ops/protected-update-routine-stage.mjs';
import {INDEPENDENT_REVIEW_DOMAIN}
  from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
const NOW=1794170000000,k=()=>generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({format:'pem',type:'spki'});
const hash=x=>createHash('sha256').update(x).digest('hex');
function fixture(){
 const signer=k(),reviewer=k(),approval=k(),other=k();
 const head='a'.repeat(40),base='b'.repeat(40);
 const manifestJson=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',commit:head,bundle:'controller-pair',
  files:[{name:'ai-github-canary-policy.mjs',sha256:'1'.repeat(64),bytes:123},
   {name:'ai-github-canary.mjs',sha256:'2'.repeat(64),bytes:321}]});
 const context={version:1,repository:'al-hub/mcp-dev-hub',
  scope:'controller-pair',head,base,prNumber:39,ciRunId:4101,
  reviewerBotId:321,reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
  operationId:'c'.repeat(32),manifestJson,packDigest:'4'.repeat(64)};
 const reviewJson=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',prNumber:39,
  head,base,reviewer:'independent-codex',reviewRunId:'5'.repeat(32),
  reviewVerdict:'PASS',findings:[],issuedAtMs:NOW-1000,
  expiresAtMs:NOW+300000});
 const codexReceipt={reviewJson,
  reviewSignatureBase64:sign(null,Buffer.from(
   INDEPENDENT_REVIEW_DOMAIN+reviewJson),signer.privateKey).toString('base64'),
  codexReviewerPublicKeyPem:pem(signer),
  issuerReviewerPublicKeyPem:pem(reviewer)};
 const rootTrust={reviewerPublicKeyPem:pem(reviewer),
  codexReviewerPublicKeyPem:pem(signer),
  approvalPublicKeyPem:pem(approval),
  approvedPackDigest:context.packDigest};
 const githubEvidence={head,base,ciRunId:4101,ciPassed:true,
  strictProtection:true};
 const officialApproval={state:'official_github_bot_review_confirmed',
  head,prNumber:39,reviewerBotId:321,reviewId:101,
  reviewActor:'mcp-dev-hub-ai-reviewer[bot]',
  reviewEvidenceId:deriveSignedCodexEvidenceId({
   reviewDigest:hash(reviewJson),packDigest:context.packDigest})};
 return {context,codexReceipt,rootTrust,githubEvidence,
  officialApproval,nowMs:NOW,other};
}
test('routine intent is canonical, exact scope and nonexecutable',()=>{
 const f=fixture(),context=f.context;
 const value={version:2,repository:context.repository,
  prNumber:39,head:context.head,base:context.base,
  ciRunId:context.ciRunId,operationId:context.operationId,
  manifestJson:context.manifestJson,
  reviewJson:f.codexReceipt.reviewJson,
  reviewSignatureBase64:f.codexReceipt.reviewSignatureBase64};
 assert.equal(parseProtectedRoutineIntent(JSON.stringify(value)).version,2);
 for(const changed of [{prNumber:40},{operationId:'invalid'},
  {script:'sudo'},{head:context.base}]){
  assert.throws(()=>parseProtectedRoutineIntent(
   JSON.stringify({...value,...changed})));
 }
});
test('signed Codex, distinct role keys and exact head/pack guard staging',()=>{
 const f=fixture();
 const result=verifyRoutineStageInputs(f);
 assert.equal(result.operationId,f.context.operationId);
 assert.equal(result.installerAuthorized,false);
 for(const patch of [
  {rootTrust:{...f.rootTrust,
   reviewerPublicKeyPem:f.rootTrust.codexReviewerPublicKeyPem}},
  {context:{...f.context,operationId:'invalid-operation-id'}},
  {officialApproval:{...f.officialApproval,
   reviewEvidenceId:'verified-wrong-evidence'}},
  {codexReceipt:{...f.codexReceipt,
   reviewSignatureBase64:'A'.repeat(86)+'=='}},
  {nowMs:NOW+300001}
 ])assert.throws(()=>verifyRoutineStageInputs({...f,...patch}));
});
test('root staging cannot be invoked from a checkout',async()=>{
 await assert.rejects(stageFixedRoutineOperation(fixture()),
   /protected_routine_stage_denied_or_unknown/);
});
test('both stage and intent modules are included in exact source package',()=>{
 for(const n of ['src/ops/protected-update-routine-stage.mjs',
  'src/ops/protected-update-routine-intent.mjs'])
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(n));
});

test('Option C staging accepts only OS-pinned three-principal trust without Bot',()=>{
 const f=fixture();
 const context={...f.context,signerMode:'wsl-local-v1'};
 delete context.reviewerBotId;
 delete context.reviewerBotActor;
 const result=verifyRoutineStageInputs({...f,context,officialApproval:null});
 assert.equal(result.installerAuthorized,false);
 assert.throws(()=>verifyRoutineStageInputs({...f,context,
  officialApproval:null,rootTrust:{...f.rootTrust,
   reviewerPublicKeyPem:f.rootTrust.codexReviewerPublicKeyPem}}));
 assert.throws(()=>verifyRoutineStageInputs({...f,context,
  officialApproval:null,githubEvidence:{...f.githubEvidence,
   strictProtection:false}}));
});
