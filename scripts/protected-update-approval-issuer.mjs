// #35 real-evidence-only second approval signer, UNINSTALLED role runner.
// Root installer must handoff the ACTUAL signed review in a root-owned
// immutable 0444 file. Only the dedicated nonroot APPROVAL UID/GID can
// use its own private key. It independently re-fetches strict GitHub CI
// and official Bot review BEFORE signing. No stdin or CLI claim accepted.
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {buildBootstrapApprovalClaim}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {BOOTSTRAP_APPROVAL_DOMAIN}
  from '../src/ops/protected-update-install-attestation.mjs';
import {assertRoleRuntimeInstalled,readFixedIssuerContext,
  readFixedIssuerToken,readFixedReviewerHandoff,
  readFixedIndependentCodexReceipt,
  fetchFixedIssuerEvidence,signFixedRolePayload}
  from '../src/ops/protected-update-issuer-runtime.mjs';

export async function issueFixedIndependentBootstrapApproval(){
  assertRoleRuntimeInstalled({
    role:'approval',moduleUrl:import.meta.url,argv:process.argv
  });
  const context=readFixedIssuerContext();
  const handoff=readFixedReviewerHandoff();
  const token=readFixedIssuerToken('approval');
  const {githubEvidence,officialApproval}=
    await fetchFixedIssuerEvidence(context,token);
  const claim=buildBootstrapApprovalClaim({
    context,githubEvidence,officialApproval,
    codexReceipt:readFixedIndependentCodexReceipt(),
    ...handoff,nowMs:Date.now()
  });
  const approvalSignatureBase64=signFixedRolePayload({
    role:'approval',domain:BOOTSTRAP_APPROVAL_DOMAIN,
    json:claim.approvalJson
  });
  return Object.freeze({
    approvalJson:claim.approvalJson,approvalSignatureBase64,
    safeToInstall:false
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await issueFixedIndependentBootstrapApproval();
    process.stdout.write(JSON.stringify({
      approvalJson:result.approvalJson,
      approvalSignatureBase64:result.approvalSignatureBase64
    })+'\n');
  }catch{
    process.stderr.write('protected_approval_issuer_denied_or_unknown\n');
    process.exitCode=1;
  }
}
