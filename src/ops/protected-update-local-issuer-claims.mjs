// #35 Option C: pure, NON-PRIVILEGED canonical local issuer claim builders.
// This module DOES NOT sign, fetch GitHub, authenticate OS identities or
// grant root access. A root-owned immutable caller MUST pin keys and obtain
// actual live GitHub evidence via its own authenticated HTTPS connection.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {BOOTSTRAP_REVIEW_DOMAIN,BOOTSTRAP_APPROVAL_DOMAIN}
  from './protected-update-install-attestation.mjs';
import {verifyIndependentSignedReview}
  from './protected-update-github-evidence.mjs';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[0-9a-f]{40}$/, HASH=/^[0-9a-f]{64}$/;
const ID=/^[0-9a-f]{32}$/, B64=/^[A-Za-z0-9+/]{86}==$/;
const CONTEXT=['version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId'];
const REVIEW=['version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId','reviewRunId',
  'verdict','findings','issuedAtMs','expiresAtMs'];
const deny=()=>{throw Error('protected_local_issuer_claim_denied');};
const exact=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).length===k.length&&k.every(x=>Object.hasOwn(o,x));
const digest=x=>createHash('sha256').update(x,'utf8').digest('hex');
const instant=t=>Number.isSafeInteger(t)&&t>0;
function pub(pem){
  if(typeof pem!=='string'||pem.length>4096||
      !pem.startsWith('-----BEGIN PUBLIC KEY-----\n')||
      !pem.endsWith('-----END PUBLIC KEY-----\n'))deny();
  let k;try{k=createPublicKey(pem);}catch{deny();}
  if(k.asymmetricKeyType!=='ed25519'||
     k.export({type:'spki',format:'pem'})!==pem)deny();
  return k;
}
function pinnedKeys(keys){
  if(!keys||!exact(keys,['codexPublicKeyPem',
    'reviewerPublicKeyPem','approvalPublicKeyPem']))deny();
  const result=['codexPublicKeyPem','reviewerPublicKeyPem',
    'approvalPublicKeyPem'].map(k=>pub(keys[k]));
  const der=result.map(k=>k.export({type:'spki',format:'der'}));
  if(der[0].equals(der[1])||der[0].equals(der[2])||
     der[1].equals(der[2]))deny();
  return result;
}
/** Separate, Bot-free, root-pinned context for local Option C.
 * This is NOT a runtime trust assertion by itself.
 */
export function parsePinnedLocalBootstrapContext(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>2048)deny();
  let c;try{c=JSON.parse(raw);}catch{deny();}
  if(!exact(c,CONTEXT)||JSON.stringify(c)!==raw||
     c.version!==1||c.repository!==REPO||
     c.scope!=='protected-bootstrap'||!SHA.test(c.head)||
     !SHA.test(c.base)||c.head===c.base||
     !SHA.test(c.baselineCommit)||c.baselineCommit===c.head||
     !HASH.test(c.packDigest)||!HASH.test(c.baselineDigest)||
     !Number.isSafeInteger(c.prNumber)||c.prNumber<=0||
     !Number.isSafeInteger(c.ciRunId)||c.ciRunId<=0)deny();
  return Object.freeze(c);
}
function established({context,githubEvidence,codexReceipt,keys,nowMs}={}){
  if(!instant(nowMs)||!context||typeof context!=='object')deny();
  const c=parsePinnedLocalBootstrapContext(JSON.stringify(context));
  const gh=githubEvidence;
  if(!exact(gh,['head','base','ciRunId','ciHead','ciPassed','strictProtection'])||
     gh.head!==c.head||gh.base!==c.base||gh.ciRunId!==c.ciRunId||
     gh.ciHead!==c.head||
     gh.ciPassed!==true||gh.strictProtection!==true)deny();
  pinnedKeys(keys);
  if(!codexReceipt||!exact(codexReceipt,
       ['reviewJson','reviewSignatureBase64']))deny();
  let codex;
  try{codex=verifyIndependentSignedReview({
    reviewJson:codexReceipt.reviewJson,
    signatureBase64:codexReceipt.reviewSignatureBase64,
    pinnedReviewerPublicKeyPem:keys.codexPublicKeyPem,
    pinnedApprovalPublicKeyPem:keys.approvalPublicKeyPem,
    head:c.head,base:c.base,prNumber:c.prNumber,nowMs,
    requiredPackDigest:c.packDigest
  });}catch{deny();}
  return {c,codex};
}
/** Pure claim: only the separately pinned reviewer OS account may sign. */
export function buildLocalBootstrapReviewerClaim(args={}){
  const {c,codex}=established(args),nowMs=args.nowMs;
  const claim={
    version:1,repository:REPO,scope:'protected-bootstrap',
    head:c.head,base:c.base,packDigest:c.packDigest,
    baselineCommit:c.baselineCommit,baselineDigest:c.baselineDigest,
    prNumber:c.prNumber,ciRunId:c.ciRunId,
    reviewRunId:codex.reviewRunId,verdict:'PASS',findings:[],
    issuedAtMs:nowMs,expiresAtMs:nowMs+120000
  };
  return Object.freeze({
    reviewJson:JSON.stringify(claim),signDomain:BOOTSTRAP_REVIEW_DOMAIN,
    safeToInstall:false,signerIdentityAuthenticated:false
  });
}
/** Pure claim: require a real separate reviewer signature, plus a separately
 * signed current Codex run and independently re-observed live CI/protection.
 * The protected APPROVAL principal must then sign the returned JSON.
 */
export function buildLocalBootstrapApprovalClaim({
  context,githubEvidence,codexReceipt,keys,nowMs,
  reviewJson,reviewSignatureBase64
}={}){
  const {c,codex}=established({context,githubEvidence,codexReceipt,
    keys,nowMs});
  if(typeof reviewJson!=='string'||Buffer.byteLength(reviewJson,'utf8')>2048||
     typeof reviewSignatureBase64!=='string'||
     !B64.test(reviewSignatureBase64))deny();
  let r;try{r=JSON.parse(reviewJson);}catch{deny();}
  if(!exact(r,REVIEW)||JSON.stringify(r)!==reviewJson||
     r.version!==1||r.repository!==REPO||r.scope!=='protected-bootstrap'||
     r.verdict!=='PASS'||!Array.isArray(r.findings)||
     r.findings.length!==0||r.reviewRunId!==codex.reviewRunId||
     !ID.test(r.reviewRunId)||!instant(r.issuedAtMs)||
     !instant(r.expiresAtMs)||r.issuedAtMs>nowMs||
     r.expiresAtMs<=nowMs||r.expiresAtMs-r.issuedAtMs>600000)deny();
  for(const field of ['head','base','packDigest','baselineCommit',
      'baselineDigest','prNumber','ciRunId'])
    if(r[field]!==c[field])deny();
  const sig=Buffer.from(reviewSignatureBase64,'base64');
  if(sig.length!==64||sig.toString('base64')!==reviewSignatureBase64)deny();
  let verified=false;
  try{verified=verify(null,Buffer.from(BOOTSTRAP_REVIEW_DOMAIN+reviewJson),
    pub(keys.reviewerPublicKeyPem),sig);}catch{deny();}
  if(!verified)deny();
  const approval={
    version:1,repository:REPO,scope:'protected-bootstrap',
    head:c.head,base:c.base,packDigest:c.packDigest,
    baselineCommit:c.baselineCommit,baselineDigest:c.baselineDigest,
    prNumber:c.prNumber,ciRunId:c.ciRunId,
    reviewDigest:digest(reviewJson),reviewRunId:codex.reviewRunId,
    issuedAtMs:nowMs,expiresAtMs:Math.min(nowMs+60000,r.expiresAtMs)
  };
  if(approval.expiresAtMs<=nowMs)deny();
  return Object.freeze({
    approvalJson:JSON.stringify(approval),signDomain:BOOTSTRAP_APPROVAL_DOMAIN,
    safeToInstall:false,signerIdentityAuthenticated:false
  });
}
