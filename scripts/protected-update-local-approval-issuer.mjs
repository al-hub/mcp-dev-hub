// #35 Option C local approver: fixed, separately owned OS principal.
// No Bot, private key in Worker, arbitrary sign command or mutable checkout.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {buildLocalBootstrapApprovalClaim}
 from '../src/ops/protected-update-local-issuer-claims.mjs';
import {assertRoleRuntimeInstalled,readFixedLocalIssuerContext,
 readFixedIssuerToken,readFixedLocalIssuerPinnedKeys,
 readFixedReviewerHandoff,readFixedIndependentCodexReceipt,
 fetchFixedLocalIssuerEvidence,signFixedRolePayload}
 from '../src/ops/protected-update-issuer-runtime.mjs';
export async function issueFixedLocalBootstrapApproval(){
 assertRoleRuntimeInstalled({
  role:'approval',moduleUrl:import.meta.url,argv:process.argv
 });
 const context=readFixedLocalIssuerContext();
 const handoff=readFixedReviewerHandoff();
 const token=readFixedIssuerToken('approval');
 const githubEvidence=await fetchFixedLocalIssuerEvidence(context,token);
 const r=readFixedIndependentCodexReceipt();
 const claim=buildLocalBootstrapApprovalClaim({
  context,githubEvidence,...handoff,
  codexReceipt:{
   reviewJson:r.reviewJson,reviewSignatureBase64:r.reviewSignatureBase64
  },
  keys:readFixedLocalIssuerPinnedKeys(),nowMs:Date.now()
 });
 const approvalSignatureBase64=signFixedRolePayload({
  role:'approval',domain:claim.signDomain,json:claim.approvalJson
 });
 return Object.freeze({
  approvalJson:claim.approvalJson,approvalSignatureBase64,
  safeToInstall:false
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const r=await issueFixedLocalBootstrapApproval();
  process.stdout.write(JSON.stringify({
   approvalJson:r.approvalJson,
   approvalSignatureBase64:r.approvalSignatureBase64
  })+'\n');
 }catch{
  process.stderr.write('protected_local_approver_denied_or_unknown\n');
  process.exitCode=1;
 }
}
