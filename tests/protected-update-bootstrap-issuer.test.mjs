import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {
  parsePinnedBootstrapIssuerContext,derivePinnedOfficialReviewRunId,
  deriveSignedCodexEvidenceId,
  buildBootstrapReviewerClaim,buildBootstrapApprovalClaim
} from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN,
  verifyProtectedBootstrapAttestations}
  from '../src/ops/protected-update-install-attestation.mjs';
import {INDEPENDENT_REVIEW_DOMAIN}
  from '../src/ops/protected-update-github-evidence.mjs';

const NOW=1794028500000;
const denied=fn=>assert.throws(fn,/protected_bootstrap_issuer_denied/);
const sha=s=>s.repeat(40),hash=s=>s.repeat(64);
const digest=t=>createHash('sha256').update(t).digest('hex');
const keys=()=>generateKeyPairSync('ed25519');
const publicPem=k=>k.publicKey.export({format:'pem',type:'spki'});
const signed=(privateKey,domain,json)=>sign(null,Buffer.from(domain+json),
  privateKey).toString('base64');
const fixture=()=>{
  const context={
    version:1,repository:'al-hub/mcp-dev-hub',
    scope:'protected-bootstrap',
    head:sha('a'),base:sha('b'),packDigest:hash('c'),
    baselineCommit:sha('d'),baselineDigest:hash('e'),
    prNumber:39,ciRunId:123456,reviewerBotId:2222,
    reviewerBotActor:'independent-reviewer[bot]'
  };
  const githubEvidence={head:context.head,base:context.base,
    ciRunId:context.ciRunId,ciPassed:true,strictProtection:true};
  // Synthetic independent Ed25519 Codex execution receipt; OS code must
  // read its actual key and bytes from fixed root-owned locations.
  const codexSigner=keys(),separateIssuerSigner=keys();
  const reviewJson=JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',
    prNumber:39,head:context.head,base:context.base,
    reviewer:'independent-codex',
    reviewRunId:'f'.repeat(32),reviewVerdict:'PASS',findings:[],
    issuedAtMs:NOW-1000,expiresAtMs:NOW+180000
  });
  const codexReceipt={
    reviewJson,
    reviewSignatureBase64:signed(codexSigner.privateKey,
      INDEPENDENT_REVIEW_DOMAIN,reviewJson),
    codexReviewerPublicKeyPem:publicPem(codexSigner),
    issuerReviewerPublicKeyPem:publicPem(separateIssuerSigner)
  };
  const codexEvidenceId=deriveSignedCodexEvidenceId({
    reviewDigest:digest(reviewJson),packDigest:context.packDigest
  });
  const officialApproval={
    state:'official_github_bot_review_confirmed',
    head:context.head,prNumber:39,reviewerBotId:2222,
    reviewActor:'independent-reviewer[bot]',reviewId:3333,
    reviewEvidenceId:codexEvidenceId
  };
  return {context,githubEvidence,officialApproval,codexReceipt};
};
function reviewed(){
  const f=fixture(),reviewer=keys(),approver=keys();
  const review=buildBootstrapReviewerClaim({...f,nowMs:NOW});
  const reviewSignatureBase64=signed(reviewer.privateKey,
    BOOTSTRAP_REVIEW_DOMAIN,review.reviewJson);
  return {...f,reviewer,approver,review,reviewSignatureBase64};
}
test('strict issuer policy binds role App identity, exact CI and verified bundle',()=>{
  const f=fixture(),raw=JSON.stringify(f.context);
  assert.deepEqual(parsePinnedBootstrapIssuerContext(raw),f.context);
  denied(()=>parsePinnedBootstrapIssuerContext(raw+' '));
  denied(()=>parsePinnedBootstrapIssuerContext(raw.replace(
    '"version":1','"version":1,"version":1')));
  for(const field of ['head','base','packDigest','baselineDigest',
    'reviewerBotId','prNumber','ciRunId','scope']){
    const c={...f.context,[field]:field==='ciRunId'?0:
      field==='reviewerBotId'||field==='prNumber'?0:'invalid'};
    denied(()=>parsePinnedBootstrapIssuerContext(JSON.stringify(c)));
  }
});
test('two independent role signatures can be validated by exact bootstrap verifier',()=>{
  const f=reviewed();
  const approval=buildBootstrapApprovalClaim({
    ...f,reviewerPublicKeyPem:publicPem(f.reviewer),
    reviewJson:f.review.reviewJson,
    reviewSignatureBase64:f.reviewSignatureBase64,nowMs:NOW+3000
  });
  const approvalSig=signed(f.approver.privateKey,
    BOOTSTRAP_APPROVAL_DOMAIN,approval.approvalJson);
  const verified=verifyProtectedBootstrapAttestations({
    reviewJson:f.review.reviewJson,
    reviewSignatureBase64:f.reviewSignatureBase64,
    approvalJson:approval.approvalJson,
    approvalSignatureBase64:approvalSig,
    reviewerPublicKeyPem:publicPem(f.reviewer),
    approvalPublicKeyPem:publicPem(f.approver),
    head:f.context.head,base:f.context.base,
    packDigest:f.context.packDigest,
    baselineCommit:f.context.baselineCommit,
    baselineDigest:f.context.baselineDigest,
    prNumber:39,ciRunId:f.context.ciRunId,nowMs:NOW+4000
  });
  assert.equal(verified.state,'attestation_bound_not_os_authorized');
  assert.equal(verified.safeToInstall,false);
  assert.equal(verified.reviewDigest,digest(f.review.reviewJson));
  assert.equal(f.review.safeToInstall,false);
  assert.equal(approval.safeToInstall,false);
});
test('reviewer issuer cannot claim PASS without actual exact verified Bot receipt',()=>{
  const f=fixture();
  for(const patch of [
    {reviewEvidenceId:null},{reviewEvidenceId:'unverified'},
    {reviewActor:'attacker[bot]'},{head:sha('f')},
    {reviewerBotId:9999},{state:'unverified'},
    {reviewId:0}
  ]){
    denied(()=>buildBootstrapReviewerClaim({
      ...f,officialApproval:{...f.officialApproval,...patch},
      nowMs:NOW
    }));
  }
  for(const patch of [
    {ciPassed:false},{strictProtection:false},{ciRunId:9999},
    {head:sha('f')},{base:sha('f')}
  ])denied(()=>buildBootstrapReviewerClaim({
    ...f,githubEvidence:{...f.githubEvidence,...patch},nowMs:NOW
  }));
});
test('reviewer run identity is derived, never Worker supplied',()=>{
  const f=fixture();
  const id=derivePinnedOfficialReviewRunId({
    head:f.context.head,reviewId:f.officialApproval.reviewId,
    evidenceId:f.officialApproval.reviewEvidenceId
  });
  assert.match(id,/^[a-f0-9]{32}$/);
  assert.notEqual(id,derivePinnedOfficialReviewRunId({
    head:f.context.head,reviewId:3334,
    evidenceId:f.officialApproval.reviewEvidenceId
  }));
  // GitHub body-only ID is not an authenticated model run ID.
  assert.notEqual(id,'f'.repeat(32));
  assert.equal(buildBootstrapReviewerClaim({...f,nowMs:NOW})
    .reviewRunId,'f'.repeat(32));
});
test('issuer refuses missing, forged or mismatched Codex signatures before PASS',()=>{
  const f=fixture();
  for(const change of [
    {codexReceipt:undefined},
    {codexReceipt:{...f.codexReceipt,reviewSignatureBase64:'AA=='}},
    {codexReceipt:{...f.codexReceipt,
      codexReviewerPublicKeyPem:publicPem(keys())}},
    {codexReceipt:{...f.codexReceipt,
      issuerReviewerPublicKeyPem:f.codexReceipt.codexReviewerPublicKeyPem}},
    {officialApproval:{...f.officialApproval,
      reviewEvidenceId:'verified-fake-untrusted-review-id'}},
    {context:{...f.context,packDigest:hash('f')}}
  ])denied(()=>buildBootstrapReviewerClaim({...f,...change,nowMs:NOW}));
  const f2=reviewed();
  denied(()=>buildBootstrapApprovalClaim({
    ...f2,codexReceipt:undefined,
    reviewerPublicKeyPem:publicPem(f2.reviewer),
    reviewJson:f2.review.reviewJson,
    reviewSignatureBase64:f2.reviewSignatureBase64,nowMs:NOW+1000
  }));
});
test('approval issuer denies fake, expired, wrong-SHA, wrong-identity review',()=>{
  const f=reviewed();
  const base={
    ...f,reviewerPublicKeyPem:publicPem(f.reviewer),
    reviewJson:f.review.reviewJson,
    reviewSignatureBase64:f.reviewSignatureBase64,nowMs:NOW+1000
  };
  const wrong=JSON.stringify({...JSON.parse(f.review.reviewJson),
    head:sha('f')});
  const corruptedSignature=Buffer.from(f.reviewSignatureBase64,'base64');
  corruptedSignature[0]^=1;
  assert.notEqual(corruptedSignature.toString('base64'),
    f.reviewSignatureBase64);
  for(const patch of [
    {reviewerPublicKeyPem:publicPem(keys())},
    {reviewSignatureBase64:corruptedSignature.toString('base64')},
    {reviewJson:wrong},
    {nowMs:NOW+130000},
    {officialApproval:{...f.officialApproval,reviewEvidenceId:'verified-fake-codex-claim'}},
    {context:{...f.context,packDigest:hash('f')}},
    {githubEvidence:{...f.githubEvidence,ciPassed:false}}
  ])denied(()=>buildBootstrapApprovalClaim({...base,...patch}));
});
test('second issuer cannot extend validity beyond reviewer signed window',()=>{
  const f=reviewed(),rev=JSON.parse(f.review.reviewJson);
  const approval=buildBootstrapApprovalClaim({
    ...f,reviewerPublicKeyPem:publicPem(f.reviewer),
    reviewJson:f.review.reviewJson,
    reviewSignatureBase64:f.reviewSignatureBase64,nowMs:NOW+115000
  });
  const a=JSON.parse(approval.approvalJson);
  assert.equal(a.expiresAtMs,rev.expiresAtMs);
  denied(()=>buildBootstrapApprovalClaim({
    ...f,reviewerPublicKeyPem:publicPem(f.reviewer),
    reviewJson:f.review.reviewJson,
    reviewSignatureBase64:f.reviewSignatureBase64,nowMs:NOW+120000
  }));
});
