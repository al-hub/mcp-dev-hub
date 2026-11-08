// #35 UNINSTALLED routine reviewer role: fixed, nonroot, read-only evidence.
// Root must pin exact operation context, Codex receipt and immutable code
// outside the Worker checkout. No CLI args/stdin, arbitrary path or verdict.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {validateProposedProtectedUpdate}
  from '../src/ops/protected-update-manifest.mjs';
import {fetchAndVerifyGitHubControllerPair}
  from '../src/ops/protected-update-github-evidence.mjs';
import {buildRoutineReviewerClaim}
  from '../src/ops/protected-update-routine-issuer.mjs';
import {assertRoleRuntimeInstalled,readFixedRoutineIssuerContext,
  readFixedIssuerToken,readFixedIndependentCodexReceipt,
  fetchFixedIssuerEvidence,signFixedRolePayload}
  from '../src/ops/protected-update-issuer-runtime.mjs';

export async function issueFixedIndependentRoutineReview(){
  assertRoleRuntimeInstalled({
    role:'reviewer',moduleUrl:import.meta.url,argv:process.argv
  });
  const context=readFixedRoutineIssuerContext();
  const token=readFixedIssuerToken('reviewer');
  const manifest=validateProposedProtectedUpdate(context.manifestJson,{
    verifiedCommit:context.head
  });
  const [{githubEvidence,officialApproval}]=await Promise.all([
    fetchFixedIssuerEvidence(context,token),
    fetchAndVerifyGitHubControllerPair({
      head:context.head,manifestFiles:manifest.files,githubToken:token
    })
  ]);
  const claim=buildRoutineReviewerClaim({
    context,githubEvidence,officialApproval,
    codexReceipt:readFixedIndependentCodexReceipt(),nowMs:Date.now()
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
    const r=await issueFixedIndependentRoutineReview();
    process.stdout.write(JSON.stringify({
      reviewJson:r.reviewJson,
      reviewSignatureBase64:r.reviewSignatureBase64
    })+'\n');
  }catch{
    process.stderr.write('protected_routine_reviewer_denied_or_unknown\n');
    process.exitCode=1;
  }
}
