// #35: deterministic two-stage bootstrap claim construction, NEVER authority
// by itself. The fixed installed issuer services alone obtain genuine HTTPS
// evidence and read their own isolated OS-private key under a pinned UID.
// Synthetic tests may pass objects to this module; those objects are NOT
// trusted signed evidence, so this library exports NO arbitrary sign action.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {BOOTSTRAP_REVIEW_DOMAIN}
  from './protected-update-install-attestation.mjs';
import {verifyIndependentSignedReview}
  from './protected-update-github-evidence.mjs';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[0-9a-f]{40}$/,HASH=/^[0-9a-f]{64}$/;
const ID=/^[0-9a-f]{32}$/,EV=/^verified-[a-z0-9-]{6,100}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const KEYS=[
  'version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId',
  'reviewerBotId','reviewerBotActor'
];
const REVIEW_KEYS=[
  'version','repository','scope','head','base','packDigest',
  'baselineCommit','baselineDigest','prNumber','ciRunId',
  'reviewRunId','verdict','findings','issuedAtMs','expiresAtMs'
];
const deny=()=>{throw Error('protected_bootstrap_issuer_denied');};
const digest=s=>createHash('sha256').update(s,'utf8').digest('hex');
const exact=(o,keys)=>o&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).length===keys.length&&
  keys.every(k=>Object.hasOwn(o,k));
const clock=n=>Number.isSafeInteger(n)&&n>0;
/** Root-owned public context file (read only by issuer principals).
 * The user/Worker is never permitted to supply its contents at runtime.
 */
export function parsePinnedBootstrapIssuerContext(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>2048)deny();
  let c;
  try{c=JSON.parse(raw);}catch{deny();}
  if(!exact(c,KEYS)||JSON.stringify(c)!==raw||
     c.version!==1||c.repository!==REPO||
     c.scope!=='protected-bootstrap'||
     !SHA.test(c.head)||!SHA.test(c.base)||c.head===c.base||
     !HASH.test(c.packDigest)||
     !SHA.test(c.baselineCommit)||c.baselineCommit===c.head||
     !HASH.test(c.baselineDigest)||
     !Number.isSafeInteger(c.prNumber)||c.prNumber<1||
     !Number.isSafeInteger(c.ciRunId)||c.ciRunId<1||
     !Number.isSafeInteger(c.reviewerBotId)||c.reviewerBotId<1||
     typeof c.reviewerBotActor!=='string'||
     !/^[a-z0-9-]+\[bot\]$/.test(c.reviewerBotActor))deny();
  return Object.freeze(c);
}
export function derivePinnedOfficialReviewRunId({
  head,reviewId,evidenceId
}={}){
  if(!SHA.test(head||'')||!Number.isSafeInteger(reviewId)||
     reviewId<=0||!EV.test(evidenceId||''))deny();
  return digest('mcp-dev-hub/verified-bot-review/v1\n'+
    head+'\n'+reviewId+'\n'+evidenceId).slice(0,32);
}
/** A deterministic link between an independently signed Codex receipt
 * and the official Bot text, not a substitute for verifying the signature.
 */
export function deriveSignedCodexEvidenceId({reviewDigest,packDigest}={}){
  if(!HASH.test(reviewDigest||'')||!HASH.test(packDigest||''))deny();
  return 'verified-'+digest(reviewDigest+'\n'+packDigest).slice(0,32);
}
function assertEvidence(c,gh,official){
  if(gh?.head!==c.head||gh.base!==c.base||
     gh.ciRunId!==c.ciRunId||gh.ciPassed!==true||
     gh.strictProtection!==true||
     official?.state!=='official_github_bot_review_confirmed'||
     official.head!==c.head||official.prNumber!==c.prNumber||
     official.reviewerBotId!==c.reviewerBotId||
     official.reviewActor!==c.reviewerBotActor||
     !Number.isSafeInteger(official.reviewId)||official.reviewId<1||
     !EV.test(official.reviewEvidenceId||''))deny();
}
/** An official Bot review body is not proof that Codex was executed.
 * The protected issuer must receive a separately pinned, Ed25519-signed
 * exact-HEAD Codex receipt from root-owned public evidence storage. The
 * signer and the independent Codex reviewer MUST be different principals.
 */
function requireSignedActualCodex({context,officialApproval,codexReceipt,nowMs}){
  if(!codexReceipt||typeof codexReceipt!=='object')deny();
  let verified;
  try{
    verified=verifyIndependentSignedReview({
      reviewJson:codexReceipt.reviewJson,
      signatureBase64:codexReceipt.reviewSignatureBase64,
      pinnedReviewerPublicKeyPem:codexReceipt.codexReviewerPublicKeyPem,
      pinnedApprovalPublicKeyPem:codexReceipt.issuerReviewerPublicKeyPem,
      head:context.head,base:context.base,prNumber:context.prNumber,
      nowMs
    });
  }catch{deny();}
  // Bind the actual signed Codex run to the immutable package fingerprint.
  // The Bot evidence ID must be derived by the trusted PR39 publisher from
  // this identical receipt, not constructed from its own review text.
  const expected=deriveSignedCodexEvidenceId({
    reviewDigest:verified.reviewDigest,packDigest:context.packDigest
  });
  if(officialApproval.reviewEvidenceId!==expected)deny();
  return verified;
}
/** Pure candidate claim only. The fixed reviewer issuer must obtain live
 * authenticated evidence itself. Signed GitHub Bot text is NOT independently
 * proof of actual Codex; the verified review publisher must enforce Codex
 * execution with independent signed provenance before posting approval.
 */
export function buildBootstrapReviewerClaim({
  codexReceipt,context,githubEvidence,officialApproval,nowMs
}={}){
  if(!context||!exact(context,KEYS)||!clock(nowMs))deny();
  parsePinnedBootstrapIssuerContext(JSON.stringify(context));
  assertEvidence(context,githubEvidence,officialApproval);
  // Never fabricate PASS or a run ID from the GitHub review's text.
  // The exact PASS and run ID below were authenticated by Ed25519.
  const codex=requireSignedActualCodex({
    context,officialApproval,codexReceipt,nowMs
  });
  const reviewRunId=codex.reviewRunId;
  const claim={
    version:1,repository:REPO,scope:'protected-bootstrap',
    head:context.head,base:context.base,
    packDigest:context.packDigest,
    baselineCommit:context.baselineCommit,
    baselineDigest:context.baselineDigest,
    prNumber:context.prNumber,ciRunId:context.ciRunId,
    reviewRunId,verdict:'PASS',findings:[],
    issuedAtMs:nowMs,expiresAtMs:nowMs+120000
  };
  return Object.freeze({
    reviewJson:JSON.stringify(claim),reviewRunId,
    signDomain:BOOTSTRAP_REVIEW_DOMAIN,
    safeToInstall:false
  });
}
/** Independently validate the pinned reviewer's actual Ed25519 signature,
 * most recent official GitHub review, and LIVE CI before constructing a
 * different principal's approval payload.
 */
export function buildBootstrapApprovalClaim({
  codexReceipt,context,githubEvidence,officialApproval,
  reviewerPublicKeyPem,reviewJson,reviewSignatureBase64,nowMs
}={}){
  if(!context||!exact(context,KEYS)||!clock(nowMs)||
     typeof reviewJson!=='string'||
     Buffer.byteLength(reviewJson,'utf8')>2048||
     typeof reviewSignatureBase64!=='string'||
     !B64.test(reviewSignatureBase64))deny();
  parsePinnedBootstrapIssuerContext(JSON.stringify(context));
  assertEvidence(context,githubEvidence,officialApproval);
  const actualCodex=requireSignedActualCodex({
    context,officialApproval,codexReceipt,nowMs
  });
  let review;
  try{review=JSON.parse(reviewJson);}catch{deny();}
  if(!exact(review,REVIEW_KEYS)||
     JSON.stringify(review)!==reviewJson||
     review.version!==1||review.repository!==REPO||
     review.scope!=='protected-bootstrap'||
     review.verdict!=='PASS'||!Array.isArray(review.findings)||
     review.findings.length!==0||
     !ID.test(review.reviewRunId)||
     !clock(review.issuedAtMs)||!clock(review.expiresAtMs)||
     review.issuedAtMs>nowMs||review.expiresAtMs<=nowMs||
     review.expiresAtMs-review.issuedAtMs>600000||
     review.reviewRunId!==actualCodex.reviewRunId)deny();
  for(const field of [
    'head','base','packDigest','baselineCommit','baselineDigest',
    'prNumber','ciRunId'
  ])if(review[field]!==context[field])deny();
  let publicKey;
  try{publicKey=createPublicKey(reviewerPublicKeyPem);}catch{deny();}
  if(publicKey.asymmetricKeyType!=='ed25519')deny();
  const sig=Buffer.from(reviewSignatureBase64,'base64');
  if(sig.length!==64||sig.toString('base64')!==reviewSignatureBase64||
     !verify(null,Buffer.from(BOOTSTRAP_REVIEW_DOMAIN+reviewJson),
       publicKey,sig))deny();
  const approval={
    version:1,repository:REPO,scope:'protected-bootstrap',
    head:context.head,base:context.base,packDigest:context.packDigest,
    baselineCommit:context.baselineCommit,
    baselineDigest:context.baselineDigest,
    prNumber:context.prNumber,ciRunId:context.ciRunId,
    reviewDigest:digest(reviewJson),reviewRunId:review.reviewRunId,
    issuedAtMs:nowMs,expiresAtMs:Math.min(nowMs+60000,
      review.expiresAtMs)
  };
  if(approval.expiresAtMs<=nowMs)deny();
  return Object.freeze({
    approvalJson:JSON.stringify(approval),safeToInstall:false
  });
}
