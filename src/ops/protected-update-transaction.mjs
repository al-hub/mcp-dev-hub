// #35 candidate transaction coordinator. NOT a standalone privileged entrypoint.
// Install only after independent review and a one-time root-owned bootstrap.
// Caller MUST be a pinned immutable supervisor, not a CLI/Issue/PR/worktree.
// Trusted evidence, Ed25519 public key, source buffers, release root and
// health observer MUST be acquired by that supervisor, never a request.
import {verifySignedProtectedUpdateApproval}
  from './protected-update-approval.mjs';
import {
  stageProtectedRelease, inspectProtectedRelease,
  inspectProtectedReleaseStaging, switchProtectedRelease,
  RELEASE_FILES
} from './protected-update-release-pointer.mjs';
import {
  beginStoredProtectedUpdateJournal,advanceStoredProtectedUpdateJournal
} from './protected-update-journal-store.mjs';

const fail=()=>{throw Error('protected_update_transaction_blocked');};
const hashes=files=>Object.freeze(Object.fromEntries(
  RELEASE_FILES.map(name=>{
    const f=files.find(row=>row.name===name);
    if(!f)fail();
    return [name,f.sha256];
  })
));
/** Require the frozen trusted proof to bind immutable, independently
 * authenticated GitHub status and reviewer observations before crypto check.
 * This structural gate is NOT independent evidence acquisition. The immutable
 * root verifier MUST query GitHub and validate review independence, GitHub
 * strict protection/CI, repo/issuer and the bytes BEFORE invoking this module.
 */
function validateTrustedProof(proof){
  if(proof===null||typeof proof!=='object'||!Object.isFrozen(proof)||
     Object.keys(proof).sort().join(',')!==
       'base,ciHead,ciPassed,ciRunId,head,independentReviewPassed,reviewBase,reviewDigest,reviewHead,strictProtection')
    fail();
  if(proof.ciPassed!==true||proof.strictProtection!==true||
     proof.independentReviewPassed!==true||
     typeof proof.ciRunId!=='number'||
     !Number.isSafeInteger(proof.ciRunId)||proof.ciRunId<=0||
     typeof proof.head!=='string'||typeof proof.base!=='string'||
     typeof proof.ciHead!=='string'||typeof proof.reviewHead!=='string'||
     typeof proof.reviewBase!=='string'||typeof proof.reviewDigest!=='string'||
     proof.ciHead!==proof.head||proof.reviewHead!==proof.head||
     proof.reviewBase!==proof.base)fail();
  return proof;
}
export function preflightProtectedUpdate({
  manifestJson,approvalJson,signatureBase64,
  pinnedPublicKey,proof,operationId,nowMs
}={}){
  const p=validateTrustedProof(proof);
  const signed=verifySignedProtectedUpdateApproval({
    manifestJson,approvalJson,signatureBase64,
    trustPublicKeyPem:pinnedPublicKey,trustedHead:p.head,
    trustedBase:p.base,trustedOperationId:operationId,nowMs
  });
  if(p.ciRunId!==signed.ciRunId||
     p.reviewDigest!==signed.reviewDigest)fail();
  return signed;
}
/** Entire operation must be driven by the separately authenticated immutable
 * entrypoint. No arbitrary commands, paths, hooks, network APIs or root keys
 * are exposed here. Missing/unknown evidence must stop, not auto-retry.
 */
export async function applyProtectedUpdateCandidate({
  root,stateDir,manifestJson,approvalJson,signatureBase64,
  pinnedPublicKey,proof,operationId,nowMs,
  contents,oldFiles,observeHealth
}={}){
  const signed=preflightProtectedUpdate({
    manifestJson,approvalJson,signatureBase64,pinnedPublicKey,
    proof,operationId,nowMs
  });
  if(typeof observeHealth!=='function'||!Array.isArray(oldFiles))fail();
  const previous=inspectProtectedRelease(root,{files:oldFiles});
  // Initial migration is separately bootstrapped and reviewed. We never
  // switch from an unknown/unbacked-up installed version.
  if(!previous||previous===signed.head)fail();
  // Verify a previously rolled-back exact release or reject a stale stage
  // BEFORE consuming a new operation ID in the persistent journal.
  inspectProtectedReleaseStaging(root,{
    commit:signed.head,files:signed.manifest.files,contents
  });
  // The journal is durably created BEFORE stage or pointer side effects.
  let j=beginStoredProtectedUpdateJournal(stateDir,{
    operationId,head:signed.head,base:signed.base,
    previousCommit:previous,
    oldHashes:hashes(oldFiles),newHashes:hashes(signed.manifest.files),
    nowMs
  });
  stageProtectedRelease(root,{
    commit:signed.head,files:signed.manifest.files,contents
  });
  j=advanceStoredProtectedUpdateJournal(stateDir,operationId,{
    expectedSequence:j.sequence,to:'switch_pending',nowMs:nowMs+1
  });
  // A lost result here is UNKNOWN: caller inspects pointer + journal and
  // does not invoke this method again with a new operation ID.
  switchProtectedRelease(root,{
    expectedCommit:previous,nextCommit:signed.head,
    nextFiles:signed.manifest.files
  });
  if(inspectProtectedRelease(root,{files:signed.manifest.files})!==signed.head)
    fail();
  j=advanceStoredProtectedUpdateJournal(stateDir,operationId,{
    expectedSequence:j.sequence,to:'switched',
    observedHashes:hashes(signed.manifest.files),nowMs:nowMs+2
  });
  // observeHealth must independently verify real Worker/Dashboard/service
  // state. A thrown/unknown result is NEVER treated as false or as PASS.
  const healthy=await observeHealth();
  if(healthy!==true&&healthy!==false)fail();
  if(healthy===true){
    j=advanceStoredProtectedUpdateJournal(stateDir,operationId,{
      expectedSequence:j.sequence,to:'verified',
      observedHashes:hashes(signed.manifest.files),
      serviceHealthVerified:true,nowMs:nowMs+3
    });
    return Object.freeze({phase:j.phase,commit:signed.head});
  }
  j=advanceStoredProtectedUpdateJournal(stateDir,operationId,{
    expectedSequence:j.sequence,to:'rollback_pending',nowMs:nowMs+3
  });
  // Always CAS: rollback never overwrites a concurrently changed pointer.
  switchProtectedRelease(root,{
    expectedCommit:signed.head,nextCommit:previous,nextFiles:oldFiles
  });
  if(inspectProtectedRelease(root,{files:oldFiles})!==previous)fail();
  j=advanceStoredProtectedUpdateJournal(stateDir,operationId,{
    expectedSequence:j.sequence,to:'rolled_back',
    observedHashes:hashes(oldFiles),nowMs:nowMs+4
  });
  return Object.freeze({phase:j.phase,commit:previous});
}
