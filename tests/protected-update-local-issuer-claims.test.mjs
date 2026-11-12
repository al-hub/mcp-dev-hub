import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {parsePinnedLocalBootstrapContext,buildLocalBootstrapReviewerClaim,
  buildLocalBootstrapApprovalClaim}
 from '../src/ops/protected-update-local-issuer-claims.mjs';
import {verifyLocalProtectedBootstrapContract}
 from '../src/ops/protected-update-local-trust-contract.mjs';
import {BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN}
 from '../src/ops/protected-update-install-attestation.mjs';
import {INDEPENDENT_REVIEW_DOMAIN_V2}
 from '../src/ops/protected-update-github-evidence.mjs';

const NOW=1794400000000, H='a'.repeat(40),B='b'.repeat(40);
const D='c'.repeat(64),ORIGINAL='d'.repeat(40),ORIGINAL_D='e'.repeat(64);
const CI=42715849215,RUN='f'.repeat(32),REPO='al-hub/mcp-dev-hub';
const key=()=>generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({format:'pem',type:'spki'});
const signature=(k,domain,json)=>sign(null,Buffer.from(domain+json),
  k.privateKey).toString('base64');
const sha=s=>createHash('sha256').update(s).digest('hex');
const denied=f=>assert.throws(f,/protected_local_issuer_claim_denied/);
function fixture(){
 const codex=key(),reviewer=key(),approver=key();
 const context={version:1,repository:REPO,scope:'protected-bootstrap',
  head:H,base:B,packDigest:D,baselineCommit:ORIGINAL,
  baselineDigest:ORIGINAL_D,prNumber:39,ciRunId:CI};
 const keys={codexPublicKeyPem:pem(codex),
  reviewerPublicKeyPem:pem(reviewer),approvalPublicKeyPem:pem(approver)};
 const codexJson=JSON.stringify({version:2,repository:REPO,
  prNumber:39,head:H,base:B,reviewer:'independent-codex',
  reviewRunId:RUN,reviewVerdict:'PASS',findings:[],
  packDigest:D,reviewInputSha256:'1'.repeat(64),
  terminalSha256:'2'.repeat(64),
  issuedAtMs:NOW-1000,expiresAtMs:NOW+120000});
 const codexReceipt={reviewJson:codexJson,
  reviewSignatureBase64:signature(codex,INDEPENDENT_REVIEW_DOMAIN_V2,codexJson)};
 const githubEvidence={head:H,base:B,ciRunId:CI,ciHead:H,
   ciPassed:true,strictProtection:true};
 const input={context,githubEvidence,codexReceipt,keys,nowMs:NOW};
 return {input,codex,reviewer,approver};
}
function reviewed(f){
 const review=buildLocalBootstrapReviewerClaim(f.input);
 const reviewSignatureBase64=signature(f.reviewer,BOOTSTRAP_REVIEW_DOMAIN,
   review.reviewJson);
 const approval=buildLocalBootstrapApprovalClaim({
  ...f.input,reviewJson:review.reviewJson,reviewSignatureBase64
 });
 return {review,reviewSignatureBase64,approval};
}
test('local signer can generate complete three-signature source contract without a Bot',()=>{
 const f=fixture(),p=reviewed(f);
 const approvalSignatureBase64=signature(f.approver,
   BOOTSTRAP_APPROVAL_DOMAIN,p.approval.approvalJson);
 const c=f.input.context;
 const result=verifyLocalProtectedBootstrapContract({
  reviewJson:p.review.reviewJson,
  reviewSignatureBase64:p.reviewSignatureBase64,
  approvalJson:p.approval.approvalJson,approvalSignatureBase64,
  reviewerPublicKeyPem:f.input.keys.reviewerPublicKeyPem,
  approvalPublicKeyPem:f.input.keys.approvalPublicKeyPem,
  codexReviewJson:f.input.codexReceipt.reviewJson,
  codexSignatureBase64:f.input.codexReceipt.reviewSignatureBase64,
  codexPublicKeyPem:f.input.keys.codexPublicKeyPem,
  head:c.head,base:c.base,packDigest:c.packDigest,
  baselineCommit:c.baselineCommit,baselineDigest:c.baselineDigest,
  prNumber:c.prNumber,ciRunId:c.ciRunId,nowMs:NOW,
  githubEvidence:f.input.githubEvidence
 });
 assert.equal(result.status,'local_three_principal_signatures_verified_source_only');
 assert.equal(result.safeToInstall,false);
 assert.equal(p.review.safeToInstall,false);
 assert.equal(p.approval.safeToInstall,false);
 assert.equal(p.review.signerIdentityAuthenticated,false);
 assert.equal(p.approval.signerIdentityAuthenticated,false);
});
test('canonical pinned context denies Worker-provided Bot claims or extra authority',()=>{
 const f=fixture();
 assert.equal(parsePinnedLocalBootstrapContext(JSON.stringify(f.input.context)).head,H);
 for(const bad of [
  {...f.input.context,reviewerBotId:123},
  {...f.input.context,scope:'root-install'},
  {...f.input.context,prNumber:0},
  {...f.input.context,head:B},
  {...f.input.context,packDigest:'invalid'}
 ])denied(()=>parsePinnedLocalBootstrapContext(JSON.stringify(bad)));
 denied(()=>parsePinnedLocalBootstrapContext(JSON.stringify(f.input.context)+' '));
});
test('all three independent pinned key identities are mandatory',()=>{
 const f=fixture(),k=f.input.keys;
 for(const keys of [
  {...k,reviewerPublicKeyPem:k.codexPublicKeyPem},
  {...k,approvalPublicKeyPem:k.reviewerPublicKeyPem},
  {...k,approvalPublicKeyPem:k.codexPublicKeyPem},
  {...k,codexPublicKeyPem:'not a PEM'}
 ])denied(()=>buildLocalBootstrapReviewerClaim({...f.input,keys}));
});
test('real signed codex evidence must be recent, complete and exact HEAD',()=>{
 const f=fixture();
 for(const patch of [
  {codexReceipt:{...f.input.codexReceipt,reviewSignatureBase64:'AA=='}},
  {codexReceipt:{...f.input.codexReceipt,reviewJson:'{"verdict":"PASS"}'}},
  {context:{...f.input.context,head:'f'.repeat(40)}},
  {nowMs:NOW+130000},
  {githubEvidence:{...f.input.githubEvidence,ciPassed:false}},
  {githubEvidence:{...f.input.githubEvidence,head:'f'.repeat(40)}},
  {githubEvidence:{...f.input.githubEvidence,ciRunId:CI+1}}
 ])denied(()=>buildLocalBootstrapReviewerClaim({...f.input,...patch}));
});
test('second signer fails on forged reviewer signature, altered claims or run mismatch',()=>{
 const f=fixture(),p=reviewed(f);
 const valid={...f.input,reviewJson:p.review.reviewJson,
   reviewSignatureBase64:p.reviewSignatureBase64};
 for(const patch of [
  {reviewSignatureBase64:'f'.repeat(88)},
  {reviewJson:p.review.reviewJson.replace('"verdict":"PASS"','"verdict":"FAIL"')},
  {nowMs:NOW+122000},
  {context:{...f.input.context,baselineDigest:'a'.repeat(64)}},
  {keys:{...f.input.keys,reviewerPublicKeyPem:pem(key())}},
  {githubEvidence:{...f.input.githubEvidence,strictProtection:false}}
 ])denied(()=>buildLocalBootstrapApprovalClaim({...valid,...patch}));
 const old=JSON.parse(p.review.reviewJson);
 old.reviewRunId='0'.repeat(32);
 const bad=JSON.stringify(old);
 denied(()=>buildLocalBootstrapApprovalClaim({...valid,reviewJson:bad,
  reviewSignatureBase64:signature(f.reviewer,BOOTSTRAP_REVIEW_DOMAIN,bad)}));
});
test('the second signer does not widen expiry or accept expired local review',()=>{
 const f=fixture(),p=reviewed(f);
 const a=JSON.parse(p.approval.approvalJson);
 const r=JSON.parse(p.review.reviewJson);
 assert.ok(a.expiresAtMs<=r.expiresAtMs);
 denied(()=>buildLocalBootstrapApprovalClaim({
   ...f.input,reviewJson:p.review.reviewJson,
   reviewSignatureBase64:p.reviewSignatureBase64,
   nowMs:r.expiresAtMs+1
 }));
});

test('real six-field GitHub evidence including ciHead must pass; mismatched ciHead must fail',()=>{
 const f=fixture();
 const six={...f.input.githubEvidence,ciHead:H};
 assert.ok(buildLocalBootstrapReviewerClaim({
   ...f.input,githubEvidence:six
 }).reviewJson);
 denied(()=>buildLocalBootstrapReviewerClaim({
   ...f.input,githubEvidence:{...six,ciHead:B}
 }));
});
