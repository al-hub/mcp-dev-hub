import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {verifyLocalProtectedBootstrapContract}
 from '../src/ops/protected-update-local-trust-contract.mjs';
import {INDEPENDENT_REVIEW_DOMAIN,INDEPENDENT_REVIEW_DOMAIN_V2}
 from '../src/ops/protected-update-github-evidence.mjs';
import {BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN}
 from '../src/ops/protected-update-install-attestation.mjs';

const NOW=1794270000000;
const H='a'.repeat(40),B='b'.repeat(40),ORIGINAL='c'.repeat(40);
const PACK='d'.repeat(64),BACKUP='e'.repeat(64);
const RUN='f'.repeat(32),CI=42629880535;
const keys=()=>generateKeyPairSync('ed25519');
const pub=k=>k.publicKey.export({format:'pem',type:'spki'});
const signed=(key,domain,json)=>sign(null,Buffer.from(domain+json),
 key.privateKey).toString('base64');
const hash=s=>createHash('sha256').update(s).digest('hex');
function fixture(){
 const codex=keys(),reviewer=keys(),approver=keys();
 const codexReviewJson=JSON.stringify({
  version:2,repository:'al-hub/mcp-dev-hub',prNumber:39,
  head:H,base:B,reviewer:'independent-codex',reviewRunId:RUN,
  reviewVerdict:'PASS',findings:[],
  packDigest:PACK,reviewInputSha256:'1'.repeat(64),
  terminalSha256:'2'.repeat(64),issuedAtMs:NOW-1000,
  expiresAtMs:NOW+30000
 });
 const reviewJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',
  scope:'protected-bootstrap',head:H,base:B,packDigest:PACK,
  baselineCommit:ORIGINAL,baselineDigest:BACKUP,
  prNumber:39,ciRunId:CI,reviewRunId:RUN,
  verdict:'PASS',findings:[],issuedAtMs:NOW-800,
  expiresAtMs:NOW+20000
 });
 const approvalJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',
  scope:'protected-bootstrap',head:H,base:B,packDigest:PACK,
  baselineCommit:ORIGINAL,baselineDigest:BACKUP,
  prNumber:39,ciRunId:CI,reviewDigest:hash(reviewJson),reviewRunId:RUN,
  issuedAtMs:NOW-300,expiresAtMs:NOW+15000
 });
 return {
  codex,reviewer,approver,
  input:{
   reviewJson,reviewSignatureBase64:signed(reviewer,
     BOOTSTRAP_REVIEW_DOMAIN,reviewJson),
   approvalJson,approvalSignatureBase64:signed(approver,
     BOOTSTRAP_APPROVAL_DOMAIN,approvalJson),
   reviewerPublicKeyPem:pub(reviewer),approvalPublicKeyPem:pub(approver),
   codexReviewJson,codexSignatureBase64:signed(codex,
     INDEPENDENT_REVIEW_DOMAIN_V2,codexReviewJson),
   codexPublicKeyPem:pub(codex),head:H,base:B,packDigest:PACK,
   baselineCommit:ORIGINAL,baselineDigest:BACKUP,
   prNumber:39,ciRunId:CI,nowMs:NOW,
   githubEvidence:{head:H,base:B,ciRunId:CI,ciHead:H,
    strictProtection:true,ciPassed:true}
  }
 };
}
const denied=a=>assert.throws(
 ()=>verifyLocalProtectedBootstrapContract(a),
 /protected_local_trust_contract_denied/
);
test('Option C authenticates three distinct signed roles without device/App inputs',()=>{
 const {input}=fixture();
 const r=verifyLocalProtectedBootstrapContract(input);
 assert.equal(r.head,H);
 assert.equal(r.ciRunId,CI);
 assert.equal(r.externalDeviceSignaturesRequired,false);
 assert.equal(r.rootInstallerAuthorized,false);
 assert.equal(r.independentOsIdentityProven,false);
 assert.equal(r.safeToInstall,false);
 assert.equal(r.safeToMerge,false);
 assert.equal(r.safeToCloseIssue,false);
});
test('unsigned self-authored claims, missing proof, extra authority flags fail closed',()=>{
 const {input}=fixture();
 denied({...input,codexSignatureBase64:'not-a-signature'});
 denied({...input,reviewSignatureBase64:'not-a-signature'});
 denied({...input,approvalSignatureBase64:'not-a-signature'});
 const {codexSignatureBase64,...noCodex}=input;
 denied(noCodex);
 denied({...input,ownerApproval:true});
 denied({...input,officialBotReview:'APPROVED'});
});
test('same principal can never sign for multiple internal roles',()=>{
 const f=fixture();
 denied({...f.input,reviewerPublicKeyPem:f.input.codexPublicKeyPem});
 denied({...f.input,approvalPublicKeyPem:f.input.reviewerPublicKeyPem});
 denied({...f.input,approvalPublicKeyPem:f.input.codexPublicKeyPem});
});
test('source, baseline, package, CI and live evidence cannot be substituted',()=>{
 const {input}=fixture();
 for(const patch of [
  {head:'9'.repeat(40)},{base:'9'.repeat(40)},
  {packDigest:'9'.repeat(64)},
  {baselineCommit:'9'.repeat(40)},
  {baselineDigest:'9'.repeat(64)},
  {prNumber:40},{ciRunId:CI+1},
  {githubEvidence:{...input.githubEvidence,ciPassed:false}},
  {githubEvidence:{...input.githubEvidence,strictProtection:false}},
  {githubEvidence:{...input.githubEvidence,head:'9'.repeat(40)}},
  {githubEvidence:{...input.githubEvidence,ciRunId:CI+1}}
 ])denied({...input,...patch});
});
test('signed independent Codex terminal and local claim MUST bind same run',()=>{
 const f=fixture();
 const bad=JSON.stringify({
  ...JSON.parse(f.input.codexReviewJson),reviewRunId:'0'.repeat(32)
 });
 denied({...f.input,codexReviewJson:bad,
  codexSignatureBase64:signed(f.codex,INDEPENDENT_REVIEW_DOMAIN_V2,bad)});
});
test('receipt expiry and changed signed claims never grant root installation',()=>{
 const f=fixture();
 denied({...f.input,nowMs:NOW+100000});
 const bad=JSON.stringify({...JSON.parse(f.input.reviewJson),
  verdict:'FAIL'});
 denied({...f.input,reviewJson:bad,
  reviewSignatureBase64:signed(f.reviewer,BOOTSTRAP_REVIEW_DOMAIN,bad)});
 const privatePem=f.codex.privateKey.export({format:'pem',type:'pkcs8'});
 denied({...f.input,codexPublicKeyPem:privatePem});
});

test('C bootstrap rejects correctly signed legacy v1 Codex receipt without source binding',()=>{
 const f=fixture(),legacy=JSON.parse(f.input.codexReviewJson);
 legacy.version=1;
 delete legacy.packDigest;
 delete legacy.reviewInputSha256;
 delete legacy.terminalSha256;
 const codexReviewJson=JSON.stringify(legacy);
 denied({...f.input,codexReviewJson,
  codexSignatureBase64:signed(f.codex,INDEPENDENT_REVIEW_DOMAIN,
   codexReviewJson)});
});
