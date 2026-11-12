// #35 UNINSTALLED candidate, pre-Bot App acceptance REVIEWER signer.
// It is NOT an attestation source: two separately installed, independently
// operated device/root gate producers must have signed real private evidence.
// This fixed no-argument nonroot role may not mint, edit or pretend test PASS.
// No checkout execution, arbitrary signer, new sudo policy, or App POST.
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyExternalAppGateReceipts}
 from '../src/ops/protected-update-app-gate-provenance.mjs';
import {APP_ACCEPTANCE_REVIEW_DOMAIN,verifyAppAcceptanceReviewer}
 from '../src/ops/protected-update-app-acceptance.mjs';
import {verifyIndependentSignedReview,
 fetchAndVerifyGitHubBootstrapEvidence}
 from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
 from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {assertRoleRuntimeInstalled,readFixedIssuerContext,
 readFixedIssuerToken,readFixedIndependentCodexReceipt,
 readFixedExternalAppGateEvidence,signFixedRolePayload}
 from '../src/ops/protected-update-issuer-runtime.mjs';

const ENTRY='/usr/local/lib/mcp-dev-hub/protected-issuer/code/'+
 'scripts/protected-update-app-acceptance-review-issuer.mjs';
const deny=()=>{throw Error('protected_app_acceptance_review_denied');};
const digest=v=>createHash('sha256').update(v).digest('hex');

/** Pure assembly from actual preverified independent evidence. Nothing here
 * fetches or manufactures a PC/Galaxy PASS or grants root/app authorization.
 */
export function assembleAppAcceptanceReviewerPacket({
 context,external,githubEvidence,codex,nowMs
}={}){
 if(!context||!external||!githubEvidence||!codex||
    !Number.isSafeInteger(nowMs)||nowMs<1||
    githubEvidence.head!==context.head||
    githubEvidence.base!==context.base||
    githubEvidence.ciRunId!==context.ciRunId||
    githubEvidence.ciPassed!==true||
    githubEvidence.strictProtection!==true||
    typeof codex.reviewDigest!=='string'||
    !/^[a-f0-9]{64}$/.test(codex.reviewDigest)||
    !Number.isSafeInteger(codex.expiresAtMs)||
    codex.expiresAtMs<=nowMs||
    !Number.isSafeInteger(external.validUntilMs)||
    external.validUntilMs<=nowMs)deny();
 const evidenceId=deriveSignedCodexEvidenceId({
  reviewDigest:codex.reviewDigest,packDigest:context.packDigest
 });
 const shortValid=Math.min(
  nowMs+90000,codex.expiresAtMs,external.validUntilMs
 );
 if(shortValid<=nowMs||!external.gates)return deny();
 const externalNames=['private_sse','pc','galaxy',
  'root_security'];
 if(Object.keys(external.gates).length!==externalNames.length||
    !externalNames.every(n=>Object.hasOwn(external.gates,n)))deny();
 const ci={headSha:context.head,verdict:'passed',
  evidenceId:'verified-ci-'+context.ciRunId};
 const security={headSha:context.head,verdict:'passed',
  evidenceId:'verified-security-'+context.ciRunId};
 const evidence={
  scope:'protected-bootstrap',prNumber:39,
  headSha:context.head,authorAgent:'agy',
  reviewerAgent:'codex',verdict:'passed',
  reviewReadonly:true,reviewIsolated:true,exitCode:0,
  evidenceId,gates:{ci,security,...external.gates}
 };
 const protectionEvidence={
  repository:'al-hub/mcp-dev-hub',branch:'main',
  headSha:context.head,enforceAdmins:true,
  requireConversationResolution:true,requiredChecks:['bootstrap'],
  requiredApprovals:0,reviewRuleAbsent:true,
  evidenceId:'verified-protection-'+context.ciRunId
 };
 const packet={
  version:2,repository:'al-hub/mcp-dev-hub',
  scope:'protected-bootstrap-app-approval',
  attestor:'independent-protected-approval',prNumber:39,
  head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:context.packDigest,
  evidence,protectionEvidence,issuedAtMs:nowMs,
  expiresAtMs:shortValid
 };
 const raw=JSON.stringify(packet);
 if(Buffer.byteLength(raw,'utf8')>12000)deny();
 return raw;
}
/** This is a candidate from the installed independently controlled reviewer
 * OS identity. Any unavailable device/root evidence fails BEFORE sign.
 */
export async function issueFixedIndependentAppAcceptanceReview(){
 assertRoleRuntimeInstalled({
  role:'reviewer',moduleUrl:import.meta.url,argv:process.argv
 });
 const context=readFixedIssuerContext();
 if(context.prNumber!==39)deny();
 const attested=readFixedExternalAppGateEvidence();
 const receipt=readFixedIndependentCodexReceipt();
 const nowMs=Date.now();
 const codex=verifyIndependentSignedReview({
  reviewJson:receipt.reviewJson,
  signatureBase64:receipt.reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem:attested.reviewerPublicKeyPem,
  head:context.head,base:context.base,prNumber:39,nowMs
 });
 let terminal;
 try{terminal=JSON.parse(receipt.reviewJson);}catch{deny();}
 if(!Number.isSafeInteger(terminal.expiresAtMs)||
    !Number.isSafeInteger(terminal.issuedAtMs))deny();
 const external=verifyExternalAppGateReceipts({
  raw:attested.raw,devicePublicKeyPem:attested.devicePublicKeyPem,
  rootPublicKeyPem:attested.rootPublicKeyPem,
  reviewerPublicKeyPem:attested.reviewerPublicKeyPem,
  approvalPublicKeyPem:attested.approvalPublicKeyPem,
  codexPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:context.packDigest,nowMs
 });
 const token=readFixedIssuerToken('reviewer');
 const githubEvidence=await fetchAndVerifyGitHubBootstrapEvidence({
  prNumber:39,head:context.head,base:context.base,
  ciRunId:context.ciRunId,githubToken:token
 });
 const finalTime=Date.now();
 verifyExternalAppGateReceipts({
  raw:attested.raw,devicePublicKeyPem:attested.devicePublicKeyPem,
  rootPublicKeyPem:attested.rootPublicKeyPem,
  reviewerPublicKeyPem:attested.reviewerPublicKeyPem,
  approvalPublicKeyPem:attested.approvalPublicKeyPem,
  codexPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  head:context.head,base:context.base,ciRunId:context.ciRunId,
  packDigest:context.packDigest,nowMs:finalTime
 });
 verifyIndependentSignedReview({
  reviewJson:receipt.reviewJson,
  signatureBase64:receipt.reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem:attested.reviewerPublicKeyPem,
  head:context.head,base:context.base,prNumber:39,nowMs:finalTime
 });
 if(finalTime<terminal.issuedAtMs)deny();
 const raw=assembleAppAcceptanceReviewerPacket({
  context,external,githubEvidence,
  codex:{...codex,expiresAtMs:terminal.expiresAtMs},
  nowMs:finalTime
 });
 const reviewSignatureBase64=signFixedRolePayload({
  role:'reviewer',domain:APP_ACCEPTANCE_REVIEW_DOMAIN,json:raw
 });
 verifyAppAcceptanceReviewer({
  raw,reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:attested.reviewerPublicKeyPem,
  head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:context.packDigest,
  nowMs:Date.now()
 });
 return Object.freeze({
  raw,reviewSignatureBase64,packetSha256:digest(raw),
  safeToInstall:false,safeToReplay:false,
  independentProducerInstalled:false
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  if(fileURLToPath(import.meta.url)!==ENTRY)deny();
  const result=await issueFixedIndependentAppAcceptanceReview();
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch{
  process.stderr.write('protected_app_acceptance_review_denied\n');
  process.exitCode=78;
 }
}
