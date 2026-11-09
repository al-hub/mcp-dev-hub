// #35 source-only collector: verifies two independent operational roles.
// Caller-supplied evidence is never installation authority; an immutable
// root supervisor must independently obtain and recheck all live evidence.
import {createHash,createPublicKey} from 'node:crypto';
import {buildRoutineApprovalClaim,parsePinnedRoutineIssuerContext}
  from './protected-update-routine-issuer.mjs';
import {verifySignedProtectedUpdateApproval}
  from './protected-update-approval.mjs';
import {parseProtectedUpdateRequest}
  from './protected-update-request.mjs';
const deny=()=>{throw Error('protected_routine_collection_denied');};
const hash=s=>createHash('sha256').update(s).digest('hex');
const pair=(x,a,b)=>x&&typeof x==='object'&&!Array.isArray(x)&&
  Object.keys(x).sort().join(',')===[a,b].sort().join(',')&&
  typeof x[a]==='string'&&typeof x[b]==='string';
function pub(pem){
  let key;try{key=createPublicKey(pem);}catch{deny();}
  if(key.asymmetricKeyType!=='ed25519')deny();
  return key.export({type:'spki',format:'der'});
}
/** Complete, validated request from real signed role outputs; does not
 * dispatch roles, write a ledger, attest provenance or grant root authority.
 */
export function assembleCollectedRoutineAuthorization({
  context,githubEvidence,officialApproval,codexReceipt,review,
  approval,rootTrust,nowMs
}={}){
  const c=parsePinnedRoutineIssuerContext(JSON.stringify(context));
  if(!Number.isSafeInteger(nowMs)||nowMs<=0||
     !pair(review,'reviewJson','reviewSignatureBase64')||
     !pair(approval,'approvalJson','approvalSignatureBase64')||
     !rootTrust||typeof rootTrust!=='object'||
     typeof rootTrust.reviewerPublicKeyPem!=='string'||
     typeof rootTrust.approvalPublicKeyPem!=='string'||
     typeof rootTrust.codexReviewerPublicKeyPem!=='string'||
     typeof codexReceipt?.issuerReviewerPublicKeyPem!=='string'||
     typeof codexReceipt?.codexReviewerPublicKeyPem!=='string')deny();
  const r=pub(rootTrust.reviewerPublicKeyPem);
  const a=pub(rootTrust.approvalPublicKeyPem);
  const x=pub(rootTrust.codexReviewerPublicKeyPem);
  if(r.equals(a)||r.equals(x)||a.equals(x)||
     !r.equals(pub(codexReceipt.issuerReviewerPublicKeyPem))||
     !x.equals(pub(codexReceipt.codexReviewerPublicKeyPem)))deny();
  // Validates the independent reviewer Ed25519 handoff, exact operation,
  // fresh signed Codex PASS and GitHub evidence bindings.
  buildRoutineApprovalClaim({
    context:c,githubEvidence,officialApproval,codexReceipt,
    reviewerPublicKeyPem:rootTrust.reviewerPublicKeyPem,
    reviewJson:review.reviewJson,
    reviewSignatureBase64:review.reviewSignatureBase64,nowMs
  });
  const verified=verifySignedProtectedUpdateApproval({
    manifestJson:c.manifestJson,approvalJson:approval.approvalJson,
    signatureBase64:approval.approvalSignatureBase64,
    trustPublicKeyPem:rootTrust.approvalPublicKeyPem,
    trustedHead:c.head,trustedBase:c.base,
    trustedOperationId:c.operationId,nowMs
  });
  let signedReview,signedApproval;
  try{
    signedReview=JSON.parse(review.reviewJson);
    signedApproval=JSON.parse(approval.approvalJson);
  }catch{deny();}
  if(verified.ciRunId!==c.ciRunId||
     verified.reviewDigest!==hash(codexReceipt.reviewJson)||
     signedApproval.issuedAtMs<signedReview.issuedAtMs||
     signedApproval.expiresAtMs>signedReview.expiresAtMs||
     signedApproval.expiresAtMs<=nowMs)deny();
  const requestJson=JSON.stringify({
    version:1,repository:'al-hub/mcp-dev-hub',prNumber:c.prNumber,
    head:c.head,base:c.base,ciRunId:c.ciRunId,operationId:c.operationId,
    manifestJson:c.manifestJson,approvalJson:approval.approvalJson,
    approvalSignatureBase64:approval.approvalSignatureBase64,
    reviewJson:codexReceipt.reviewJson,
    reviewSignatureBase64:codexReceipt.reviewSignatureBase64,
    routineReviewJson:review.reviewJson,
    routineReviewSignatureBase64:review.reviewSignatureBase64
  });
  parseProtectedUpdateRequest(requestJson);
  return Object.freeze({
    status:'collected_routine_request_source_only',
    operationId:c.operationId,requestJson,
    installerAuthorized:false,safeToReplay:false
  });
}
