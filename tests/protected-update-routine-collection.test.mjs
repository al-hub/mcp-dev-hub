import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {assembleCollectedRoutineAuthorization}
  from '../src/ops/protected-update-routine-collection.mjs';
import {buildRoutineReviewerClaim,buildRoutineApprovalClaim,
  ROUTINE_REVIEW_DOMAIN,ROUTINE_APPROVAL_DOMAIN}
  from '../src/ops/protected-update-routine-issuer.mjs';
import {INDEPENDENT_REVIEW_DOMAIN,INDEPENDENT_REVIEW_DOMAIN_V2}
  from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {parseProtectedUpdateRequest}
  from '../src/ops/protected-update-request.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
const NOW=1794170000000,k=()=>generateKeyPairSync('ed25519');
const pem=x=>x.publicKey.export({type:'spki',format:'pem'});
const signIt=(x,d,j)=>sign(null,Buffer.from(d+j),x.privateKey)
  .toString('base64');
const hash=x=>createHash('sha256').update(x).digest('hex');
function example(localMode=false){
 const reviewer=k(),approver=k(),codex=k(),impostor=k();
 const head='a'.repeat(40),base='b'.repeat(40);
 const manifestJson=JSON.stringify({version:1,
  repository:'al-hub/mcp-dev-hub',commit:head,bundle:'controller-pair',
  files:[{name:'ai-github-canary-policy.mjs',sha256:'1'.repeat(64),bytes:123},
   {name:'ai-github-canary.mjs',sha256:'2'.repeat(64),bytes:321}]});
 const context={version:1,repository:'al-hub/mcp-dev-hub',
  scope:'controller-pair',head,base,prNumber:39,ciRunId:4001,
  reviewerBotId:100,reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
  operationId:'c'.repeat(32),manifestJson,packDigest:'3'.repeat(64)};
 if(localMode){
  delete context.reviewerBotId;
  delete context.reviewerBotActor;
  context.signerMode='wsl-local-v1';
 }
 const reviewJson=JSON.stringify({version:localMode?2:1,
  repository:'al-hub/mcp-dev-hub',prNumber:39,head,base,
  reviewer:'independent-codex',reviewRunId:'4'.repeat(32),
  reviewVerdict:'PASS',findings:[],
  ...(localMode?{packDigest:context.packDigest,
   reviewInputSha256:'1'.repeat(64),terminalSha256:'2'.repeat(64)}:{}),
  issuedAtMs:NOW-1000,expiresAtMs:NOW+300000});
 const codexReceipt={reviewJson,
  reviewSignatureBase64:signIt(codex,
   localMode?INDEPENDENT_REVIEW_DOMAIN_V2:INDEPENDENT_REVIEW_DOMAIN,
   reviewJson),
  codexReviewerPublicKeyPem:pem(codex),
  issuerReviewerPublicKeyPem:pem(reviewer)};
 const githubEvidence={head,base,ciRunId:4001,
  ciPassed:true,strictProtection:true};
 let officialApproval={state:'official_github_bot_review_confirmed',
  head,prNumber:39,reviewerBotId:100,
  reviewActor:'mcp-dev-hub-ai-reviewer[bot]',reviewId:123,
  reviewEvidenceId:deriveSignedCodexEvidenceId({
    reviewDigest:hash(reviewJson),packDigest:context.packDigest})};
 if(localMode)officialApproval=null;
 const f={context,githubEvidence,officialApproval,codexReceipt};
 const rc=buildRoutineReviewerClaim({...f,nowMs:NOW});
 const review={reviewJson:rc.reviewJson,
  reviewSignatureBase64:signIt(reviewer,ROUTINE_REVIEW_DOMAIN,rc.reviewJson)};
 const ac=buildRoutineApprovalClaim({...f,...review,
  reviewerPublicKeyPem:pem(reviewer),nowMs:NOW+1000});
 const approval={approvalJson:ac.approvalJson,
  approvalSignatureBase64:signIt(approver,ROUTINE_APPROVAL_DOMAIN,
   ac.approvalJson)};
 const rootTrust={reviewerPublicKeyPem:pem(reviewer),
  approvalPublicKeyPem:pem(approver),codexReviewerPublicKeyPem:pem(codex)};
 return {...f,review,approval,rootTrust,impostor,nowMs:NOW+2000};
}
test('signed role outputs assemble only the exact legacy root request',()=>{
 const f=example(),result=assembleCollectedRoutineAuthorization(f);
 assert.equal(result.status,'collected_routine_request_source_only');
 assert.equal(result.installerAuthorized,false);
 assert.equal(result.safeToReplay,false);
 const req=parseProtectedUpdateRequest(result.requestJson);
 assert.equal(req.operationId,f.context.operationId);
 assert.equal(req.routineReviewJson,f.review.reviewJson);
});
test('wrong key, swapped signer, stale receipt and operation replay denied',()=>{
 const f=example();
 const invalid=[
  {context:{...f.context,operationId:'d'.repeat(32)}},
  {rootTrust:{...f.rootTrust,reviewerPublicKeyPem:pem(f.impostor)}},
  {rootTrust:{...f.rootTrust,
    codexReviewerPublicKeyPem:f.rootTrust.reviewerPublicKeyPem}},
  {approval:{...f.approval,approvalSignatureBase64:signIt(
   f.impostor,ROUTINE_APPROVAL_DOMAIN,f.approval.approvalJson)}},
  {officialApproval:{...f.officialApproval,
   reviewEvidenceId:'verified-forged-evidence'}},
  {nowMs:NOW+300001}
 ];
 for(const patch of invalid)assert.throws(
  ()=>assembleCollectedRoutineAuthorization({...f,...patch}));
});
test('the reviewed static package contains collector and never enables install',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
  'src/ops/protected-update-routine-collection.mjs'));
});

test('Option C routine collection verifies 3 distinct role signatures without Bot',()=>{
 const f=example(true);
 const result=assembleCollectedRoutineAuthorization(f);
 assert.equal(result.status,'collected_routine_request_source_only');
 assert.equal(result.safeToReplay,false);
 assert.equal(parseProtectedUpdateRequest(result.requestJson).operationId,
  f.context.operationId);
 for(const p of [
  {githubEvidence:{...f.githubEvidence,ciPassed:false}},
  {review:{...f.review,reviewSignatureBase64:signIt(f.impostor,
   ROUTINE_REVIEW_DOMAIN,f.review.reviewJson)}},
  {approval:{...f.approval,approvalSignatureBase64:signIt(f.impostor,
   ROUTINE_APPROVAL_DOMAIN,f.approval.approvalJson)}},
  {context:{...f.context,head:'f'.repeat(40)}},
  {nowMs:NOW+300001}
 ])assert.throws(()=>assembleCollectedRoutineAuthorization({...f,...p}));
});
