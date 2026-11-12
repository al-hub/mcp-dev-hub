// #35 Option C local protected reviewer: only installed immutable OS runtime.
// No Bot approval, device attestor, stdin, Worker-supplied flags or paths.
// This does not prove the pinned Codex signer is genuinely independent;
 // an owner-audited root bootstrap MUST establish that boundary before use.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {buildLocalBootstrapReviewerClaim}
 from '../src/ops/protected-update-local-issuer-claims.mjs';
import {assertRoleRuntimeInstalled,readFixedLocalIssuerContext,
 readFixedIssuerToken,readFixedLocalIssuerPinnedKeys,
 readFixedIndependentCodexReceipt,fetchFixedLocalIssuerEvidence,
 signFixedRolePayload}
 from '../src/ops/protected-update-issuer-runtime.mjs';
export async function issueFixedLocalBootstrapReview(){
 assertRoleRuntimeInstalled({
  role:'reviewer',moduleUrl:import.meta.url,argv:process.argv
 });
 const context=readFixedLocalIssuerContext();
 const token=readFixedIssuerToken('reviewer');
 const githubEvidence=await fetchFixedLocalIssuerEvidence(context,token);
 const r=readFixedIndependentCodexReceipt();
 const claim=buildLocalBootstrapReviewerClaim({
  context,githubEvidence,
  codexReceipt:{
   reviewJson:r.reviewJson,reviewSignatureBase64:r.reviewSignatureBase64
  },
  keys:readFixedLocalIssuerPinnedKeys(),nowMs:Date.now()
 });
 const reviewSignatureBase64=signFixedRolePayload({
  role:'reviewer',domain:claim.signDomain,json:claim.reviewJson
 });
 return Object.freeze({
  reviewJson:claim.reviewJson,reviewSignatureBase64,safeToInstall:false
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const r=await issueFixedLocalBootstrapReview();
  process.stdout.write(JSON.stringify({
   reviewJson:r.reviewJson,reviewSignatureBase64:r.reviewSignatureBase64
  })+'\n');
 }catch{
  process.stderr.write('protected_local_reviewer_denied_or_unknown\n');
  process.exitCode=1;
 }
}
