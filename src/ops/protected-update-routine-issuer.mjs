// #35 fixed, data-only controller-pair claim builders, NOT installed.
// These functions never sign, elevate, fetch credentials, or accept unpinned
// OS paths. Only immutable separate reviewer/approval role runners may sign.
import {createHash,createPublicKey,verify} from 'node:crypto';
import {validateProposedProtectedUpdate}
  from './protected-update-manifest.mjs';
import {verifyIndependentSignedReview}
  from './protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from './protected-update-bootstrap-issuer.mjs';
import {APPROVAL_DOMAIN}
  from './protected-update-approval.mjs';

export const ROUTINE_REVIEW_DOMAIN=
  'mcp-dev-hub/routine-independent-review/v1\\n';
export const ROUTINE_APPROVAL_DOMAIN=APPROVAL_DOMAIN;
const REPO='al-hub/mcp-dev-hub';
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const ID=/^[a-f0-9]{32}$/,B64=/^[A-Za-z0-9+/]{86}==$/;
const CONTEXT_KEYS=[
  'version','repository','scope','head','base','prNumber','ciRunId',
  'reviewerBotId','reviewerBotActor','operationId','manifestJson',
  'packDigest'
];
const LOCAL_CONTEXT_KEYS=[...CONTEXT_KEYS.filter(k=>
  !['reviewerBotId','reviewerBotActor'].includes(k)),'signerMode'];
const REVIEW_KEYS=[
  'version','repository','scope','head','base','prNumber','ciRunId',
  'operationId','manifestSha256','reviewDigest','reviewRunId',
  'verdict','issuedAtMs','expiresAtMs'
];
const deny=()=>{throw Error('protected_routine_issuer_denied');};
const hash=s=>createHash('sha256').update(s,'utf8').digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&
  !Array.isArray(o)&&Object.keys(o).length===keys.length&&
  keys.every(k=>Object.hasOwn(o,k));
const time=t=>Number.isSafeInteger(t)&&t>0;

/** Context is root-authenticated, root-owned immutable per operation.
 * A worker-supplied object is NEVER equivalent to that OS provenance.
 */
export function parsePinnedRoutineIssuerContext(raw){
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>6500)deny();
  let c;
  try{c=JSON.parse(raw);}catch{deny();}
  const local=c?.signerMode==='wsl-local-v1';
  if(!exact(c,local?LOCAL_CONTEXT_KEYS:CONTEXT_KEYS)||
     JSON.stringify(c)!==raw||
     c.version!==1||c.repository!==REPO||c.scope!=='controller-pair'||
     c.prNumber!==39||!SHA.test(c.head||'')||
     !SHA.test(c.base||'')||c.head===c.base||
     !Number.isSafeInteger(c.ciRunId)||c.ciRunId<=0||
     (!local&&(!Number.isSafeInteger(c.reviewerBotId)||
       c.reviewerBotId<=0||
       c.reviewerBotActor!=='mcp-dev-hub-ai-reviewer[bot]'))||
     !ID.test(c.operationId||'')||!HASH.test(c.packDigest||'')||
     typeof c.manifestJson!=='string')deny();
  let manifest;
  try{
    manifest=validateProposedProtectedUpdate(c.manifestJson,{
      verifiedCommit:c.head
    });
  }catch{deny();}
  if(manifest.commit!==c.head||manifest.files.length!==2)deny();
  return Object.freeze({...c});
}
function bound(context,githubEvidence,officialApproval,codexReceipt,nowMs){
  const c=parsePinnedRoutineIssuerContext(JSON.stringify(context));
  if(!time(nowMs)||githubEvidence?.head!==c.head||
     githubEvidence.base!==c.base||
     githubEvidence.ciRunId!==c.ciRunId||
     githubEvidence.ciPassed!==true||
     githubEvidence.strictProtection!==true||
     (c.signerMode==='wsl-local-v1' ? officialApproval!==null :
     officialApproval?.state!=='official_github_bot_review_confirmed'||
     officialApproval.head!==c.head||
     officialApproval.prNumber!==39||
     officialApproval.reviewerBotId!==c.reviewerBotId||
     officialApproval.reviewActor!==c.reviewerBotActor||
     !Number.isSafeInteger(officialApproval.reviewId)||
     officialApproval.reviewId<=0))deny();
  let codex;
  try{
    codex=verifyIndependentSignedReview({
      reviewJson:codexReceipt?.reviewJson,
      signatureBase64:codexReceipt?.reviewSignatureBase64,
      pinnedReviewerPublicKeyPem:codexReceipt?.codexReviewerPublicKeyPem,
      pinnedApprovalPublicKeyPem:codexReceipt?.issuerReviewerPublicKeyPem,
      head:c.head,base:c.base,prNumber:39,nowMs
    });
  }catch{deny();}
  if(c.signerMode!=='wsl-local-v1'&&
     officialApproval.reviewEvidenceId!==deriveSignedCodexEvidenceId({
       reviewDigest:codex.reviewDigest,packDigest:c.packDigest
     }))deny();
  return {context:c,codex};
}

/** Only complete live evidence + independently signed Codex PASS leads to
 * a deterministic claim. This remains non-authoritative without the pinned
 * reviewer OS principal signing it and the approval principal rechecking.
 */
export function buildRoutineReviewerClaim({
  context,githubEvidence,officialApproval,codexReceipt,nowMs
}={}){
  const {context:c,codex}=bound(context,githubEvidence,
    officialApproval,codexReceipt,nowMs);
  const claim={
    version:1,repository:REPO,scope:'controller-pair',
    head:c.head,base:c.base,prNumber:39,ciRunId:c.ciRunId,
    operationId:c.operationId,manifestSha256:hash(c.manifestJson),
    reviewDigest:codex.reviewDigest,reviewRunId:codex.reviewRunId,
    verdict:'PASS',issuedAtMs:nowMs,expiresAtMs:nowMs+120000
  };
  return Object.freeze({
    reviewJson:JSON.stringify(claim),signDomain:ROUTINE_REVIEW_DOMAIN,
    operationId:c.operationId,safeToInstall:false
  });
}

/** Revalidate live GitHub + signed Codex, then authenticate the OTHER
 * reviewer's operation-bound Ed25519 handoff before constructing a strictly
 * bounded approval payload. No unverified or caller-selected sign domain.
 */
export function buildRoutineApprovalClaim({
  context,githubEvidence,officialApproval,codexReceipt,
  reviewerPublicKeyPem,reviewJson,reviewSignatureBase64,nowMs
}={}){
  const {context:c,codex}=bound(context,githubEvidence,
    officialApproval,codexReceipt,nowMs);
  if(typeof reviewJson!=='string'||
     Buffer.byteLength(reviewJson,'utf8')>2048||
     typeof reviewSignatureBase64!=='string'||!B64.test(reviewSignatureBase64))
    deny();
  let r;
  try{r=JSON.parse(reviewJson);}catch{deny();}
  if(!exact(r,REVIEW_KEYS)||JSON.stringify(r)!==reviewJson||
     r.version!==1||r.repository!==REPO||r.scope!=='controller-pair'||
     r.verdict!=='PASS'||r.head!==c.head||r.base!==c.base||
     r.prNumber!==39||r.ciRunId!==c.ciRunId||
     r.operationId!==c.operationId||
     r.manifestSha256!==hash(c.manifestJson)||
     r.reviewDigest!==codex.reviewDigest||
     r.reviewRunId!==codex.reviewRunId||
     !time(r.issuedAtMs)||!time(r.expiresAtMs)||
     r.issuedAtMs>nowMs||r.expiresAtMs<=nowMs||
     r.expiresAtMs-r.issuedAtMs>600000)deny();
  try{
    const pub=createPublicKey(reviewerPublicKeyPem);
    const codexPub=createPublicKey(
      codexReceipt.codexReviewerPublicKeyPem);
    if(pub.asymmetricKeyType!=='ed25519'||
       codexPub.asymmetricKeyType!=='ed25519'||
       pub.export({type:'spki',format:'der'}).equals(
         codexPub.export({type:'spki',format:'der'})))deny();
    const sig=Buffer.from(reviewSignatureBase64,'base64');
    if(sig.length!==64||sig.toString('base64')!==reviewSignatureBase64||
       !verify(null,Buffer.from(ROUTINE_REVIEW_DOMAIN+reviewJson),
         pub,sig))deny();
  }catch{deny();}
  const approval={
    version:1,repository:REPO,scope:'controller-pair',
    head:c.head,base:c.base,manifestSha256:hash(c.manifestJson),
    ciRunId:c.ciRunId,ciHead:c.head,
    reviewHead:c.head,reviewBase:c.base,
    reviewDigest:codex.reviewDigest,reviewVerdict:'PASS',
    operationId:c.operationId,issuedAtMs:nowMs,
    expiresAtMs:Math.min(nowMs+60000,r.expiresAtMs)
  };
  if(approval.expiresAtMs<=nowMs)deny();
  return Object.freeze({
    approvalJson:JSON.stringify(approval),
    signDomain:ROUTINE_APPROVAL_DOMAIN,safeToInstall:false
  });
}
