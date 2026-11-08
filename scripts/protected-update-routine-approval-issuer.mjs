// #35 UNINSTALLED routine approval signer, separate OS approval principal.
// No arbitrary payload or signing endpoint: fixed root-staged context and
// separately signed reviewer handoff must match live GitHub+Codex evidence.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {validateProposedProtectedUpdate}
  from '../src/ops/protected-update-manifest.mjs';
import {fetchAndVerifyGitHubControllerPair}
  from '../src/ops/protected-update-github-evidence.mjs';
import {buildRoutineApprovalClaim}
  from '../src/ops/protected-update-routine-issuer.mjs';
import {assertRoleRuntimeInstalled,readFixedRoutineIssuerContext,
  readFixedRoutineReviewerHandoff,readFixedIssuerToken,
  readFixedIndependentCodexReceipt,fetchFixedIssuerEvidence,
  signFixedRolePayload}
  from '../src/ops/protected-update-issuer-runtime.mjs';

export async function issueFixedIndependentRoutineApproval(){
  assertRoleRuntimeInstalled({
    role:'approval',moduleUrl:import.meta.url,argv:process.argv
  });
  const context=readFixedRoutineIssuerContext();
  const handoff=readFixedRoutineReviewerHandoff();
  const token=readFixedIssuerToken('approval');
  const manifest=validateProposedProtectedUpdate(context.manifestJson,{
    verifiedCommit:context.head
  });
  const [{githubEvidence,officialApproval}]=await Promise.all([
    fetchFixedIssuerEvidence(context,token),
    fetchAndVerifyGitHubControllerPair({
      head:context.head,manifestFiles:manifest.files,githubToken:token
    })
  ]);
  const claim=buildRoutineApprovalClaim({
    context,githubEvidence,officialApproval,
    codexReceipt:readFixedIndependentCodexReceipt(),
    ...handoff,nowMs:Date.now()
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
    const r=await issueFixedIndependentRoutineApproval();
    process.stdout.write(JSON.stringify({
      approvalJson:r.approvalJson,
      approvalSignatureBase64:r.approvalSignatureBase64
    })+'\\n');
  }catch{
    process.stderr.write('protected_routine_approver_denied_or_unknown\\n');
    process.exitCode=1;
  }
}
