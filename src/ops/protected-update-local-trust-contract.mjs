// #35 Option C — SOURCE-ONLY protected-local proof contract, not an issuer.
// No private keys, signer callbacks, OS identity assertions or install action.
// Production MUST independently pin these three distinct public keys to
// separate protected OS principals and obtain live HTTPS GitHub evidence from
// root-owned immutable code; caller-supplied objects are only test fixtures.
import {createPublicKey} from 'node:crypto';
import {verifyIndependentSignedReview}
  from './protected-update-github-evidence.mjs';
import {verifyProtectedBootstrapAttestations}
  from './protected-update-install-attestation.mjs';

const FIELDS=[
 'reviewJson','reviewSignatureBase64','approvalJson',
 'approvalSignatureBase64','reviewerPublicKeyPem','approvalPublicKeyPem',
 'codexReviewJson','codexSignatureBase64','codexPublicKeyPem',
 'head','base','packDigest','baselineCommit','baselineDigest',
 'prNumber','ciRunId','nowMs','githubEvidence'
];
const deny=()=>{throw Error('protected_local_trust_contract_denied');};
function publicDer(pem){
 if(typeof pem!=='string'||pem.length>4096||
    !pem.startsWith('-----BEGIN PUBLIC KEY-----\n')||
    !pem.endsWith('-----END PUBLIC KEY-----\n')||
    pem.includes('PRIVATE KEY'))deny();
 let k;try{k=createPublicKey(pem);}catch{deny();}
 if(k.asymmetricKeyType!=='ed25519'||
    k.export({type:'spki',format:'pem'})!==pem)deny();
 return k.export({type:'spki',format:'der'});
}
/**
 * Verify exact-head CI and THREE unrelated short-lived role signatures:
 * (1) independent pinned Codex terminal runner; (2) protected reviewer;
 * (3) protected approver. Neither GitHub Bot approval nor PC/Galaxy keys
 * are cryptographic inputs. This pure check is NEVER root authorization.
 *
 * ROOT-ONLY caller obligations (not attestable by this function):
 * - Authenticate real completed model output, not a model-made PASS string.
 * - Independently fetch real PR, BASE, required CI and branch rules via HTTPS.
 * - Prove each signer private key is held by its own immutable OS principal.
 * - Pin original bytes/package and obtain one authenticated owner bootstrap.
 * - Enforce allowlist, deny unknown/replay and verify physical acceptance.
 */
export function verifyLocalProtectedBootstrapContract(input={}){
 if(input===null||typeof input!=='object'||Array.isArray(input)||
    Object.keys(input).length!==FIELDS.length||
    !FIELDS.every(k=>Object.hasOwn(input,k)))deny();
 const c=input,gh=c.githubEvidence;
 if(gh===null||typeof gh!=='object'||Array.isArray(gh)||
    Object.keys(gh).sort().join(',')!==
      'base,ciHead,ciPassed,ciRunId,head,strictProtection'||
    gh.head!==c.head||gh.base!==c.base||
    gh.ciRunId!==c.ciRunId||gh.ciHead!==c.head||
    gh.ciPassed!==true||gh.strictProtection!==true)deny();
 const keys=[
  publicDer(c.codexPublicKeyPem),
  publicDer(c.reviewerPublicKeyPem),
  publicDer(c.approvalPublicKeyPem)
 ];
 for(let i=0;i<keys.length;i++)
  for(let j=i+1;j<keys.length;j++)
   if(keys[i].equals(keys[j]))deny();
 let codex,bound;
 try{
  codex=verifyIndependentSignedReview({
   reviewJson:c.codexReviewJson,
   signatureBase64:c.codexSignatureBase64,
   pinnedReviewerPublicKeyPem:c.codexPublicKeyPem,
   pinnedApprovalPublicKeyPem:c.approvalPublicKeyPem,
   head:c.head,base:c.base,prNumber:c.prNumber,nowMs:c.nowMs,
    requiredPackDigest:c.packDigest
  });
  bound=verifyProtectedBootstrapAttestations({
   reviewJson:c.reviewJson,
   reviewSignatureBase64:c.reviewSignatureBase64,
   approvalJson:c.approvalJson,
   approvalSignatureBase64:c.approvalSignatureBase64,
   reviewerPublicKeyPem:c.reviewerPublicKeyPem,
   approvalPublicKeyPem:c.approvalPublicKeyPem,
   head:c.head,base:c.base,packDigest:c.packDigest,
   baselineCommit:c.baselineCommit,baselineDigest:c.baselineDigest,
   prNumber:c.prNumber,ciRunId:c.ciRunId,nowMs:c.nowMs
  });
 }catch{deny();}
 if(codex.reviewRunId!==bound.reviewRunId||
    codex.head!==bound.head||codex.base!==bound.base||
    bound.safeToInstall!==false)deny();
 return Object.freeze({
  status:'local_three_principal_signatures_verified_source_only',
  head:c.head,base:c.base,ciRunId:c.ciRunId,
  packDigest:c.packDigest,reviewRunId:codex.reviewRunId,
  rootInstallerAuthorized:false,independentOsIdentityProven:false,
  externalDeviceSignaturesRequired:false,
  signedRootOperatingReceiptIssued:false,
  safeToInstall:false,safeToMerge:false,safeToCloseIssue:false
 });
}
