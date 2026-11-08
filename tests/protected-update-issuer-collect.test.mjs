import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {verifyCollectedBootstrapSignatures,
  collectFixedBootstrapIssuerAttestations}
  from '../scripts/protected-update-issuer-collect.mjs';
import {
  buildBootstrapReviewerClaim,buildBootstrapApprovalClaim,
  deriveSignedCodexEvidenceId
} from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN}
  from '../src/ops/protected-update-install-attestation.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
import {INDEPENDENT_REVIEW_DOMAIN}
  from '../src/ops/protected-update-github-evidence.mjs';

const NOW=1794028500000;
const key=()=>generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const signed=(k,domain,json)=>sign(null,
  Buffer.from(domain+json),k.privateKey).toString('base64');
function scenario(){
  const reviewer=key(),approver=key(),codexSigner=key();
  const context={
    version:1,repository:'al-hub/mcp-dev-hub',scope:'protected-bootstrap',
    head:'a'.repeat(40),base:'b'.repeat(40),packDigest:'c'.repeat(64),
    baselineCommit:'d'.repeat(40),baselineDigest:'e'.repeat(64),
    prNumber:39,ciRunId:1242,
    reviewerBotId:23234,reviewerBotActor:'official-reviewer[bot]'
  };
  const githubEvidence={head:context.head,base:context.base,
    ciRunId:context.ciRunId,ciPassed:true,strictProtection:true};
  const codexReviewJson=JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',
    prNumber:39,head:context.head,base:context.base,
    reviewer:'independent-codex',reviewRunId:'f'.repeat(32),
    reviewVerdict:'PASS',findings:[],
    issuedAtMs:NOW-1000,expiresAtMs:NOW+150000
  });
  const codexReceipt={
    reviewJson:codexReviewJson,
    reviewSignatureBase64:signed(
      codexSigner,INDEPENDENT_REVIEW_DOMAIN,codexReviewJson),
    codexReviewerPublicKeyPem:pem(codexSigner),
    issuerReviewerPublicKeyPem:pem(reviewer)
  };
  const reviewDigest=createHash('sha256')
    .update(codexReviewJson).digest('hex');
  const evidenceId=deriveSignedCodexEvidenceId({
    reviewDigest,packDigest:context.packDigest
  });
  const officialApproval={
    state:'official_github_bot_review_confirmed',
    head:context.head,prNumber:39,reviewerBotId:23234,
    reviewActor:'official-reviewer[bot]',reviewId:44321,
    reviewEvidenceId:evidenceId
  };
  const claimed=buildBootstrapReviewerClaim({
    context,githubEvidence,officialApproval,codexReceipt,nowMs:NOW
  });
  const review={reviewJson:claimed.reviewJson,
    reviewSignatureBase64:signed(reviewer,
      BOOTSTRAP_REVIEW_DOMAIN,claimed.reviewJson)};
  const approve=buildBootstrapApprovalClaim({
    context,githubEvidence,officialApproval,codexReceipt,...review,
    reviewerPublicKeyPem:pem(reviewer),nowMs:NOW+1000
  });
  const approval={approvalJson:approve.approvalJson,
    approvalSignatureBase64:signed(approver,
      BOOTSTRAP_APPROVAL_DOMAIN,approve.approvalJson)};
  return {context,review,approval,rootTrust:{
    reviewerPublicKeyPem:pem(reviewer),
    approvalPublicKeyPem:pem(approver)
  }};
}
test('two role signatures are accepted by exact existing root bootstrap guard',()=>{
  const f=scenario();
  const p=verifyCollectedBootstrapSignatures({...f,nowMs:NOW+2000});
  assert.equal(p.state,'two_sigs_bound_needs_owner_bootstrap');
  assert.equal(p.safeToInstall,false);
  assert.match(p.reviewRunId,/^[a-f0-9]{32}$/);
});
test('approval signer/role substitution or stale review is rejected',()=>{
  const f=scenario();
  assert.throws(()=>verifyCollectedBootstrapSignatures({
    ...f,rootTrust:{...f.rootTrust,
      reviewerPublicKeyPem:f.rootTrust.approvalPublicKeyPem},nowMs:NOW+2000
  }));
  assert.throws(()=>verifyCollectedBootstrapSignatures({
    ...f,context:{...f.context,packDigest:'f'.repeat(64)},nowMs:NOW+2000
  }));
  assert.throws(()=>verifyCollectedBootstrapSignatures({
    ...f,nowMs:NOW+130000
  }));
});
test('trusted issuer staging and collector source are pinned in the same bundle',()=>{
  for(const path of [
    'scripts/protected-update-issuer-collect.mjs',
    'scripts/protected-update-issuer-stage.mjs'
  ])assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(path));
});
test('root collector cannot run imported from mutable checkout',async()=>{
  await assert.rejects(collectFixedBootstrapIssuerAttestations(),
    /protected_issuer_collect_denied_or_unknown/);
});
test('direct checkout invocation exits nonzero and emits no private evidence',()=>{
  const path=fileURLToPath(new URL(
    '../scripts/protected-update-issuer-collect.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[path],{
    encoding:'utf8',input:'',timeout:5000,maxBuffer:1024
  });
  assert.equal(r.status,1);
  assert.equal(r.stdout,'');
  assert.match(r.stderr,/protected_issuer_collect_denied_or_unknown/);
});
