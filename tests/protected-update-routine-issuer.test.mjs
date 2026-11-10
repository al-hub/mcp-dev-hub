import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {INDEPENDENT_REVIEW_DOMAIN,INDEPENDENT_REVIEW_DOMAIN_V2}
  from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {
  ROUTINE_REVIEW_DOMAIN,ROUTINE_APPROVAL_DOMAIN,
  parsePinnedRoutineIssuerContext,buildRoutineReviewerClaim,
  buildRoutineApprovalClaim
} from '../src/ops/protected-update-routine-issuer.mjs';
import {verifySignedProtectedUpdateApproval,APPROVAL_DOMAIN}
  from '../src/ops/protected-update-approval.mjs';
const H='a'.repeat(40),B='b'.repeat(40),OID='c'.repeat(32);
const now=1794170000000;
const sha=b=>createHash('sha256').update(b).digest('hex');
const keys=()=>generateKeyPairSync('ed25519');
const codex=keys(),reviewer=keys(),approval=keys(),other=keys();
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const signClaim=(domain,json,key)=>sign(null,Buffer.from(domain+json),
  key.privateKey).toString('base64');
function fixture(){
 const manifestJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',commit:H,
  bundle:'controller-pair',files:[
   {name:'ai-github-canary-policy.mjs',sha256:'1'.repeat(64),bytes:123},
   {name:'ai-github-canary.mjs',sha256:'2'.repeat(64),bytes:321}
  ]
 });
 const context={
  version:1,repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
  head:H,base:B,prNumber:39,ciRunId:42534767804,
  reviewerBotId:12345,reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
  operationId:OID,manifestJson,packDigest:'3'.repeat(64)
 };
 const reviewJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',prNumber:39,
  head:H,base:B,reviewer:'independent-codex',
  reviewRunId:'4'.repeat(32),reviewVerdict:'PASS',findings:[],
  issuedAtMs:now-1000,expiresAtMs:now+300000
 });
 const codexReceipt={
  reviewJson,reviewSignatureBase64:signClaim(
   INDEPENDENT_REVIEW_DOMAIN,reviewJson,codex),
  codexReviewerPublicKeyPem:pem(codex),
  issuerReviewerPublicKeyPem:pem(reviewer)
 };
 const githubEvidence={head:H,base:B,ciRunId:context.ciRunId,
  ciPassed:true,strictProtection:true};
 const officialApproval={state:'official_github_bot_review_confirmed',
  head:H,prNumber:39,reviewerBotId:context.reviewerBotId,
  reviewActor:context.reviewerBotActor,reviewId:101,
  reviewEvidenceId:deriveSignedCodexEvidenceId({
   reviewDigest:sha(reviewJson),packDigest:context.packDigest
  })};
 return {context,githubEvidence,officialApproval,codexReceipt,
  nowMs:now};
}
const denied=/protected_routine_issuer_denied/;
function reviewPair(f){
 const r=buildRoutineReviewerClaim(f);
 const reviewSignatureBase64=signClaim(
  ROUTINE_REVIEW_DOMAIN,r.reviewJson,reviewer);
 return {reviewerPublicKeyPem:pem(reviewer),reviewJson:r.reviewJson,
  reviewSignatureBase64};
}
test('routine signed approval is exactly accepted by existing root verifier',()=>{
 const f=fixture();
 const parsed=parsePinnedRoutineIssuerContext(
  JSON.stringify(f.context));
 assert.equal(parsed.operationId,OID);
 const signedReview=reviewPair(f);
 const result=buildRoutineApprovalClaim({...f,...signedReview});
 assert.equal(result.signDomain,APPROVAL_DOMAIN);
 assert.equal(ROUTINE_APPROVAL_DOMAIN,APPROVAL_DOMAIN);
 const approvalSignatureBase64=signClaim(
  result.signDomain,result.approvalJson,approval);
 const verified=verifySignedProtectedUpdateApproval({
  manifestJson:f.context.manifestJson,
  approvalJson:result.approvalJson,
  signatureBase64:approvalSignatureBase64,
  trustPublicKeyPem:pem(approval),trustedHead:H,
  trustedBase:B,trustedOperationId:OID,nowMs:now
 });
 assert.equal(verified.operationId,OID);
 assert.equal(verified.reviewDigest,sha(f.codexReceipt.reviewJson));
 assert.equal(verified.manifest.commit,H);
 assert.equal(result.safeToInstall,false);
});
test('context refuses changed operation, manifest, scope, bot or ambiguous JSON',()=>{
 const {context}=fixture();
 const raw=JSON.stringify(context);
 for(const patch of [
  {scope:'protected-bootstrap'}, {operationId:'not-id'},
  {prNumber:40},{reviewerBotActor:'worker'},
  {packDigest:'bad'}, {manifestJson:context.manifestJson+' '},
  {manifestJson:context.manifestJson.replace(H,B)},
  {manifestJson:context.manifestJson.replace('controller-pair','other')}
 ])assert.throws(()=>parsePinnedRoutineIssuerContext(
  JSON.stringify({...context,...patch})),denied);
 for(const invalid of [raw+' ',raw.replace('"version":1',
   '"version":1,"version":1')])assert.throws(
  ()=>parsePinnedRoutineIssuerContext(invalid),denied);
});
test('wrong or expired Codex signed receipt and forged Bot proof fail before claim',()=>{
 const f=fixture();
 for(const p of [
  {codexReceipt:{...f.codexReceipt,
   reviewSignatureBase64:signClaim(INDEPENDENT_REVIEW_DOMAIN,
    f.codexReceipt.reviewJson,other)}},
  {codexReceipt:{...f.codexReceipt,
   codexReviewerPublicKeyPem:pem(reviewer)}},
  {officialApproval:{...f.officialApproval,reviewEvidenceId:'verified-fake-fake'}},
  {githubEvidence:{...f.githubEvidence,ciPassed:false}},
  {nowMs:now+300001}
 ])assert.throws(()=>buildRoutineReviewerClaim({...f,...p}),denied);
});
test('approval issuer rejects reviewer-signature substitution and operation replay',()=>{
 const f=fixture(),r=reviewPair(f);
 for(const p of [
  {reviewSignatureBase64:signClaim(
   ROUTINE_REVIEW_DOMAIN,r.reviewJson,other)},
  {reviewerPublicKeyPem:pem(codex)},
  {context:{...f.context,operationId:'d'.repeat(32)}},
  {context:{...f.context,manifestJson:f.context.manifestJson.replace(
   '"bytes":321','"bytes":322')}},
  {reviewJson:r.reviewJson.replace('"verdict":"PASS"',
   '"verdict":"UNKNOWN"')},
  {nowMs:now+120001}
 ])assert.throws(()=>buildRoutineApprovalClaim({...f,...r,...p}),denied);
});

test('Option C routine claim requires genuine independent signatures and live CI without Bot',()=>{
 const f=fixture();
 const localContext={...f.context,signerMode:'wsl-local-v1'};
 delete localContext.reviewerBotId;
 delete localContext.reviewerBotActor;
 const json=JSON.stringify({...JSON.parse(f.codexReceipt.reviewJson),
  version:2,packDigest:localContext.packDigest,
  reviewInputSha256:'1'.repeat(64),terminalSha256:'2'.repeat(64)});
 const local={...f,context:localContext,officialApproval:null,
  codexReceipt:{...f.codexReceipt,reviewJson:json,
   reviewSignatureBase64:signClaim(INDEPENDENT_REVIEW_DOMAIN_V2,json,codex)}};
 assert.equal(parsePinnedRoutineIssuerContext(
  JSON.stringify(localContext)).signerMode,'wsl-local-v1');
 const reviewerProof=reviewPair(local);
 const claim=buildRoutineApprovalClaim({...local,...reviewerProof});
 const sig=signClaim(ROUTINE_APPROVAL_DOMAIN,claim.approvalJson,approval);
 assert.equal(verifySignedProtectedUpdateApproval({
  manifestJson:localContext.manifestJson,
  approvalJson:claim.approvalJson,signatureBase64:sig,
  trustPublicKeyPem:pem(approval),trustedHead:H,trustedBase:B,
  trustedOperationId:OID,nowMs:now
 }).operationId,OID);
 for(const p of [
  {githubEvidence:{...local.githubEvidence,ciPassed:false}},
  {codexReceipt:{...local.codexReceipt,
   reviewSignatureBase64:signClaim(INDEPENDENT_REVIEW_DOMAIN,
    local.codexReceipt.reviewJson,other)}},
  {context:{...localContext,reviewerBotId:12345}},
  {context:{...localContext,head:'f'.repeat(40)}},
  {nowMs:now+300001}
 ])assert.throws(()=>buildRoutineReviewerClaim({...local,...p}),denied);
 assert.throws(()=>buildRoutineApprovalClaim({...local,
  ...reviewerProof,reviewSignatureBase64:signClaim(
   ROUTINE_REVIEW_DOMAIN,reviewerProof.reviewJson,other)}),denied);
});
