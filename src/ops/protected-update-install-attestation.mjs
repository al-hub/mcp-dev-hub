// #35: strict *read-only* two-principal one-shot bootstrap attestation gate.
// This candidate module is not an issuer, signer, root installer, or an
// authorization by itself. Production must pin the two unrelated public keys
// and validate real reviewer/CI provenance from immutable trusted services.
// No private keys, tokens or dynamic issuer paths are accepted here.
import {createHash,createPublicKey,verify} from 'node:crypto';

export const BOOTSTRAP_REVIEW_DOMAIN=
  'mcp-dev-hub/bootstrap-independent-review/v1\n';
export const BOOTSTRAP_APPROVAL_DOMAIN=
  'mcp-dev-hub/bootstrap-approval/v1\n';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const ID=/^[0-9a-f]{32}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const REVIEW_KEYS=[
  'version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId','reviewRunId',
  'verdict','findings','issuedAtMs','expiresAtMs'
];
const APPROVAL_KEYS=[
  'version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId','reviewDigest',
  'reviewRunId','issuedAtMs','expiresAtMs'
];
const deny=()=>{throw Error('protected_bootstrap_attestation_denied');};
const exact=(o,k)=>o!==null&&typeof o==='object'&&
  !Array.isArray(o)&&Object.keys(o).length===k.length&&
  k.every(x=>Object.hasOwn(o,x));
const digest=t=>createHash('sha256').update(t,'utf8').digest('hex');

function canonical(raw,keys){
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>2048||
     raw.length===0)deny();
  let obj;
  try{obj=JSON.parse(raw);}catch{deny();}
  if(!exact(obj,keys)||JSON.stringify(obj)!==raw)deny();
  return obj;
}
function validWindow(data,nowMs){
  if(!Number.isSafeInteger(data.issuedAtMs)||data.issuedAtMs<1||
     !Number.isSafeInteger(data.expiresAtMs)||
     data.issuedAtMs>nowMs||data.expiresAtMs<nowMs||
     data.expiresAtMs<=data.issuedAtMs||
     data.expiresAtMs-data.issuedAtMs>600000)deny();
}
function signedBy(publicKeyPem,signatureBase64,domain,payload){
  if(typeof signatureBase64!=='string'||!B64.test(signatureBase64))deny();
  const sig=Buffer.from(signatureBase64,'base64');
  if(sig.length!==64||sig.toString('base64')!==signatureBase64)deny();
  let key;
  try{key=createPublicKey(publicKeyPem);}catch{deny();}
  if(key.asymmetricKeyType!=='ed25519')deny();
  if(!verify(null,Buffer.from(domain+payload,'utf8'),key,sig))deny();
  return key.export({type:'spki',format:'der'});
}
/** Verify separately signed, short-lived, exact-HEAD installer evidence.
 * This confirms cryptographic identity and scope BINDING, not whether the
 * reviewer actually ran Codex, the approval signer was truly independent,
 * GitHub CI was queried, or OS authorization exists. Those require a
 * trusted, unmodifiable issuer/root-supervisor implementation.
 */
export function verifyProtectedBootstrapAttestations({
  reviewJson,reviewSignatureBase64,approvalJson,approvalSignatureBase64,
  reviewerPublicKeyPem,approvalPublicKeyPem,
  head,base,packDigest,baselineCommit,baselineDigest,prNumber,ciRunId,nowMs
}={}){
  if(typeof head!=='string'||!SHA.test(head)||
     typeof base!=='string'||!SHA.test(base)||head===base||
     typeof packDigest!=='string'||!HASH.test(packDigest)||
     typeof baselineCommit!=='string'||!SHA.test(baselineCommit)||
     baselineCommit===head||
     typeof baselineDigest!=='string'||!HASH.test(baselineDigest)||
     !Number.isSafeInteger(prNumber)||prNumber<1||
     !Number.isSafeInteger(ciRunId)||ciRunId<=0||
     !Number.isSafeInteger(nowMs)||nowMs<=0)deny();

  const review=canonical(reviewJson,REVIEW_KEYS);
  const approval=canonical(approvalJson,APPROVAL_KEYS);
  for(const claim of [review,approval]){
    if(claim.version!==1||claim.repository!==REPO||
       claim.scope!=='protected-bootstrap'||
       claim.head!==head||claim.base!==base||
       claim.packDigest!==packDigest||
       claim.baselineCommit!==baselineCommit||
       claim.baselineDigest!==baselineDigest||
       claim.prNumber!==prNumber||claim.ciRunId!==ciRunId||
       typeof claim.reviewRunId!=='string'||!ID.test(claim.reviewRunId))
      deny();
    validWindow(claim,nowMs);
  }
  if(review.verdict!=='PASS'||!Array.isArray(review.findings)||
     review.findings.length!==0||
     review.reviewRunId!==approval.reviewRunId||
     approval.reviewDigest!==digest(reviewJson)||
     approval.issuedAtMs<review.issuedAtMs||
     approval.expiresAtMs>review.expiresAtMs)deny();

  const reviewKey=signedBy(reviewerPublicKeyPem,
    reviewSignatureBase64,BOOTSTRAP_REVIEW_DOMAIN,reviewJson);
  const approvalKey=signedBy(approvalPublicKeyPem,
    approvalSignatureBase64,BOOTSTRAP_APPROVAL_DOMAIN,approvalJson);
  if(reviewKey.equals(approvalKey))deny();
  return Object.freeze({
    state:'attestation_bound_not_os_authorized',
    head,base,packDigest,baselineCommit,baselineDigest,prNumber,ciRunId,
    reviewRunId:review.reviewRunId,reviewDigest:digest(reviewJson),
    safeToInstall:false
  });
}
