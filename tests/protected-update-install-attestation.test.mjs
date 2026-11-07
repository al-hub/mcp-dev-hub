import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
  BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN,
  verifyProtectedBootstrapAttestations
} from '../src/ops/protected-update-install-attestation.mjs';

const H='a'.repeat(40),B='b'.repeat(40),C='c'.repeat(40);
const P='d'.repeat(64),L='e'.repeat(64),PR=39,CI=42334635648,T=1794023500000;
const ID='f'.repeat(32);
const hash=s=>createHash('sha256').update(s).digest('hex');
const key=()=>generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
function fixture(){
  const reviewer=key(),approver=key();
  const review={
    version:1,repository:'al-hub/mcp-dev-hub',scope:'protected-bootstrap',
    head:H,base:B,packDigest:P,baselineCommit:C,baselineDigest:L,
    prNumber:PR,ciRunId:CI,reviewRunId:ID,verdict:'PASS',findings:[],
    issuedAtMs:T-1000,expiresAtMs:T+30000
  };
  const approval={
    version:1,repository:'al-hub/mcp-dev-hub',scope:'protected-bootstrap',
    head:H,base:B,packDigest:P,baselineCommit:C,baselineDigest:L,
    prNumber:PR,ciRunId:CI,reviewDigest:hash(JSON.stringify(review)),reviewRunId:ID,
    issuedAtMs:T-500,expiresAtMs:T+20000
  };
  const reviewJson=JSON.stringify(review),approvalJson=JSON.stringify(approval);
  const signature=(privateKey,domain,json)=>sign(null,
    Buffer.from(domain+json),privateKey).toString('base64');
  const args={
    reviewJson,approvalJson,
    reviewSignatureBase64:signature(reviewer.privateKey,
      BOOTSTRAP_REVIEW_DOMAIN,reviewJson),
    approvalSignatureBase64:signature(approver.privateKey,
      BOOTSTRAP_APPROVAL_DOMAIN,approvalJson),
    reviewerPublicKeyPem:pem(reviewer),
    approvalPublicKeyPem:pem(approver),
    head:H,base:B,packDigest:P,baselineCommit:C,baselineDigest:L,
    prNumber:PR,ciRunId:CI,nowMs:T
  };
  return {args,reviewer,approver,review,approval,signature};
}
const denied=fn=>assert.throws(fn,/protected_bootstrap_attestation_denied/);
test('two unrelated issuer signatures bind exact reviewed source, CI, baseline',()=>{
  const f=fixture(), result=verifyProtectedBootstrapAttestations(f.args);
  assert.equal(result.state,'attestation_bound_not_os_authorized');
  assert.equal(result.safeToInstall,false);
  assert.equal(result.head,H);
  assert.equal(result.packDigest,P);
  assert.equal(result.reviewDigest,hash(f.args.reviewJson));
});
test('caller-chosen package digest or head/base/CI/baseline cannot be changed',()=>{
  const f=fixture();
  for(const field of ['head','base','packDigest','baselineCommit',
    'baselineDigest','prNumber','ciRunId']){
    const value=field==='ciRunId'?CI+1:field==='prNumber'?PR+1:
      field.endsWith('Digest')||field==='packDigest'?'0'.repeat(64):
      '0'.repeat(40);
    denied(()=>verifyProtectedBootstrapAttestations({
      ...f.args,[field]:value
    }));
  }
});
test('reviewer signature cannot be used as approval issuer signature',()=>{
  const f=fixture();
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,
    approvalPublicKeyPem:f.args.reviewerPublicKeyPem,
    approvalSignatureBase64:f.args.reviewSignatureBase64
  }));
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,approvalPublicKeyPem:f.args.reviewerPublicKeyPem
  }));
});
test('signature bit flips, incorrect trust root and malformed base64 are denied',()=>{
  const f=fixture();
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,reviewSignatureBase64:'A'+f.args.reviewSignatureBase64.slice(1)
  }));
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,approvalPublicKeyPem:pem(key())
  }));
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,approvalSignatureBase64:'not-base64'
  }));
});
test('canonical JSON parser denies injected or duplicated trust claims',()=>{
  const f=fixture();
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,reviewJson:f.args.reviewJson.replace('"version":1',
      '"version":1,"version":1')
  }));
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,approvalJson:f.args.approvalJson+' '
  }));
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,reviewJson:'{'+ 'x'.repeat(4096)+'}'
  }));
});
test('unsigned changed review verdict or nonzero findings is refused',()=>{
  const f=fixture();
  for(const changes of [{verdict:'FAIL'},{findings:['critical']}]){
    const reviewJson=JSON.stringify({...f.review,...changes});
    denied(()=>verifyProtectedBootstrapAttestations({...f.args,
      reviewJson,
      reviewSignatureBase64:f.signature(f.reviewer.privateKey,
        BOOTSTRAP_REVIEW_DOMAIN,reviewJson)
    }));
  }
});
test('approval review digest and run identity must match review exactly',()=>{
  const f=fixture();
  for(const changes of [
    {reviewDigest:'1'.repeat(64)},{reviewRunId:'1'.repeat(32)},
    {scope:'generic-admin'}]){
    const approvalJson=JSON.stringify({...f.approval,...changes});
    denied(()=>verifyProtectedBootstrapAttestations({...f.args,
      approvalJson,
      approvalSignatureBase64:f.signature(f.approver.privateKey,
        BOOTSTRAP_APPROVAL_DOMAIN,approvalJson)
    }));
  }
});
test('no expired, future, or excessive window can authorize installation',()=>{
  const f=fixture();
  for(const nowMs of [T-3000,T+40000]){
    denied(()=>verifyProtectedBootstrapAttestations({...f.args,nowMs}));
  }
  const reviewJson=JSON.stringify({...f.review,expiresAtMs:T+1000000});
  denied(()=>verifyProtectedBootstrapAttestations({...f.args,
    reviewJson,reviewSignatureBase64:f.signature(f.reviewer.privateKey,
      BOOTSTRAP_REVIEW_DOMAIN,reviewJson)
  }));
});
test('approval validity cannot begin before reviewed evidence exists',()=>{
  const f=fixture();
  const approvalJson=JSON.stringify({...f.approval,issuedAtMs:T-2000});
  denied(()=>verifyProtectedBootstrapAttestations({...f.args,
    approvalJson,approvalSignatureBase64:f.signature(f.approver.privateKey,
      BOOTSTRAP_APPROVAL_DOMAIN,approvalJson)
  }));
});
test('signature from another domain is not interchangeable',()=>{
  const f=fixture();
  const bad=f.signature(f.reviewer.privateKey,
    BOOTSTRAP_APPROVAL_DOMAIN,f.args.reviewJson);
  denied(()=>verifyProtectedBootstrapAttestations({
    ...f.args,reviewSignatureBase64:bad
  }));
});
