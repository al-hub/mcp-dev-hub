// #35 real-evidence-only reviewer signer, UNINSTALLED role-runner candidate.
// Root bootstrap must stage exact signed source to fixed root-owned
// readable issuer-runtime (NOT the mutable Git checkout), pin public
// context, and start this under the dedicated nonroot REVIEWER UID/GID.
// No CLI flags/stdin/Worker-issued PASS is accepted.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {buildBootstrapReviewerClaim}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {assertRoleRuntimeInstalled,readFixedIssuerContext,
  readFixedIssuerToken,readFixedIndependentCodexReceipt,
  fetchFixedIssuerEvidence,
  signFixedRolePayload}
  from '../src/ops/protected-update-issuer-runtime.mjs';

export async function issueFixedIndependentBootstrapReview(){
  assertRoleRuntimeInstalled({
    role:'reviewer',moduleUrl:import.meta.url,argv:process.argv
  });
  const context=readFixedIssuerContext();
  const token=readFixedIssuerToken('reviewer');
  const {githubEvidence,officialApproval}=
    await fetchFixedIssuerEvidence(context,token);
  const claim=buildBootstrapReviewerClaim({
    context,githubEvidence,officialApproval,
    codexReceipt:readFixedIndependentCodexReceipt(),nowMs:Date.now()
  });
  const reviewSignatureBase64=signFixedRolePayload({
    role:'reviewer',domain:claim.signDomain,json:claim.reviewJson
  });
  return Object.freeze({
    reviewJson:claim.reviewJson,reviewSignatureBase64,
    safeToInstall:false
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await issueFixedIndependentBootstrapReview();
    process.stdout.write(JSON.stringify({
      reviewJson:result.reviewJson,
      reviewSignatureBase64:result.reviewSignatureBase64
    })+'\n');
  }catch{
    process.stderr.write('protected_reviewer_issuer_denied_or_unknown\n');
    process.exitCode=1;
  }
}
