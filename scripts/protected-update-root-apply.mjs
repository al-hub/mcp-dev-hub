// #35 UNINSTALLED root-owned, fixed-command protected two-file updater.
// Do not run this script from a checkout, allow arbitrary sudo args/env, or
// install it before independent privileged code audit and one-time owner
// authorization. A signed request is DATA, never a shell command.
import {constants,closeSync,fstatSync,openSync,readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';

import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {assertPinnedProtectedLauncher,withProtectedOperationGuard}
  from '../src/ops/protected-update-operation-guard.mjs';
import {parseProtectedUpdateRequest}
  from '../src/ops/protected-update-request.mjs';
import {parseProtectedRoutineIntent}
  from '../src/ops/protected-update-routine-intent.mjs';
import {collectFixedRoutineIssuerAttestations}
  from './protected-update-issuer-collect.mjs';
import {assertFixedRootProtectedUpdateLayout}
  from '../src/ops/protected-update-root-layout.mjs';
import {preflightAuthenticatedProtectedUpdate,readRootProtectedUpdateTrust}
  from '../src/ops/protected-update-root-evidence.mjs';
import {inspectProtectedCurrentSnapshot,RELEASE_FILES}
  from '../src/ops/protected-update-release-pointer.mjs';
import {applyProtectedUpdateCandidate,preflightProtectedUpdateAdmission}
  from '../src/ops/protected-update-transaction.mjs';
import {verifyIndependentSignedReview,
  fetchAndVerifyOfficialReviewerApproval}
  from '../src/ops/protected-update-github-evidence.mjs';
import {verifySignedProtectedUpdateApproval}
  from '../src/ops/protected-update-approval.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {buildRoutineApprovalClaim}
  from '../src/ops/protected-update-routine-issuer.mjs';
import {observeProtectedWorkerHealth}
  from '../src/ops/protected-update-health-probe.mjs';

const FIXED='/usr/local/lib/mcp-dev-hub/protected-updater/code/scripts/protected-update-root-apply.mjs';
const ROOT='/usr/local/lib/mcp-dev-hub';
const STATE='/var/lib/mcp-dev-hub/protected-update';
const TRUST='/etc/mcp-dev-hub/protected-update';
const REQ_LIMIT=16000;
const deny=()=>{throw Error('protected_root_apply_denied');};
/** Synthetic group inspection only; root authority comes from OS getgroups
 * after setgroups([]), not from a caller-supplied array.
 */
export function rootSupplementaryGroupsCleared(groups,effectiveGid){
  return Array.isArray(groups)&&groups.length<=1&&
    groups.every(g=>g===effectiveGid);
}
function requireFixedRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
     fileURLToPath(import.meta.url)!==FIXED||process.argv.length!==2)
    deny();
}
function privateDecimal(name){
  const fd=openSync(TRUST+'/'+name,
    constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.nlink!==1||st.uid!==0||
       (st.mode&0o777)!==0o400||st.size<1||st.size>16)deny();
    const raw=readFileSync(fd,'utf8').trim();
    if(!/^[0-9]{1,9}$/.test(raw))deny();
    const value=Number(raw);
    if(!Number.isSafeInteger(value))deny();
    return value;
  }finally{closeSync(fd);}
}
function pinnedLauncherDigest(){
  const fd=openSync(TRUST+'/approved-pack-digest',
    constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  let hash;
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
       (st.mode&0o777)!==0o400||st.size<1||st.size>128)deny();
    hash=readFileSync(fd,'utf8').trim();
    if(!/^[a-f0-9]{64}$/.test(hash))deny();
  }finally{closeSync(fd);}
  const checked=verifyProtectedBootstrapPack({
    outputPath:ROOT+'/protected-updater',expectedManifestSha256:hash
  });
  if(checked.status!=='source_only_unprivileged_no_go')deny();
  const wrapper=checked.files.find(x=>
    x.path==='scripts/protected-update-controller-wrapper.mjs');
  if(!wrapper||!/^[a-f0-9]{64}$/.test(wrapper.sha256))deny();
  return wrapper.sha256;
}
function hashes(files){
  if(!Array.isArray(files)||files.length!==2||
     !RELEASE_FILES.every(name=>files.some(f=>f?.name===name)))
    deny();
  return Object.freeze(Object.fromEntries(files.map(f=>[f.name,f.sha256])));
}
/** Buffered stream is bounded and expires. A caller is never permitted to
 * choose an executable, token, key, repository, root, health unit or workdir.
 */
async function readRequest(){
  return await new Promise((resolve,reject)=>{
    let total=0,parts=[],done=false;
    const fail=()=>finish(Error('protected_root_request_denied'));
    const timer=setTimeout(fail,10000);
    function finish(error){
      if(done)return;
      done=true;clearTimeout(timer);
      process.stdin.off('data',data);
      process.stdin.off('end',end);
      process.stdin.off('error',fail);
      process.stdin.pause();
      if(error)reject(error);
      else resolve(Buffer.concat(parts).toString('utf8'));
      parts=[];
    }
    function data(chunk){
      total+=chunk.length;
      if(total>REQ_LIMIT){fail();return;}
      parts.push(chunk);
    }
    function end(){finish(null);}
    process.stdin.on('data',data);
    process.stdin.on('end',end);
    process.stdin.on('error',fail);
    process.stdin.resume();
  });
}
/** No side effects until independently signed live CI/source proof and a
 * real, fixed Worker+Dashboard+syntax health baseline are established.
 * After staging, only the immutable transaction may write the version pair.
 * Unexpected/uncertain health throws UNKNOWN and never triggers blind replay.
 */
export async function applyOneProtectedUpdateFixedRoot(){
  requireFixedRoot();
  // Child health probes run under the pinned Worker identity; never leave
  // inherited root supplementary groups accessible inside their sandbox.
  try{
    if(typeof process.setgroups!=='function')deny();
    process.setgroups([]);
    if(!rootSupplementaryGroupsCleared(
      process.getgroups(),process.getgid()))deny();
  }catch{deny();}
  const raw=await readRequest();
  assertFixedRootProtectedUpdateLayout();
  // Confirm trusted launcher and root pins BEFORE any routine staging write.
  // A version-2 intent still requires real external Codex/Bot/CI evidence,
  // and it cannot itself sign any approval.
  const launcherHash=pinnedLauncherDigest();
  const trust=readRootProtectedUpdateTrust();
  let candidate;
  try{candidate=JSON.parse(raw);}catch{deny();}
  let req;
  if(candidate?.version===2){
    const intent=parseProtectedRoutineIntent(raw);
    const collected=await collectFixedRoutineIssuerAttestations({intent});
    req=parseProtectedUpdateRequest(collected.requestJson);
  }else{
    req=parseProtectedUpdateRequest(raw);
  }
  // Authenticate the complete signed request BEFORE taking the durable
  // root mutation lock. Invalid or stale proofs may not alter controller.

  assertFixedOperationalIssuerIsolation();
  const uid=privateDecimal('worker-uid');
  const gid=privateDecimal('worker-gid');
  if(uid===0||gid===0)deny();
  const verified=await preflightAuthenticatedProtectedUpdate({
    ...req,nowMs:Date.now()
  });
  const reviewerBotId=privateDecimal('reviewer-bot-id');
  if(reviewerBotId<=0)deny();
  const official=await fetchAndVerifyOfficialReviewerApproval({
    prNumber:req.prNumber,head:req.head,reviewerBotId,
    githubToken:trust.githubToken,nowMs:Date.now()
  });
  if(official.state!=='official_github_bot_review_confirmed'||
     official.reviewEvidenceId!==deriveSignedCodexEvidenceId({
       reviewDigest:verified.proof.reviewDigest,
       packDigest:trust.approvedPackDigest
     }))deny();
  // The routine reviewer signature is a distinct operational trust boundary,
  // NEVER interchangeable with the independent Codex signed receipt.
  const routineContext=Object.freeze({
    version:1,repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
    head:req.head,base:req.base,prNumber:req.prNumber,
    ciRunId:req.ciRunId,reviewerBotId,
    reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
    operationId:req.operationId,manifestJson:req.manifestJson,
    packDigest:trust.approvedPackDigest
  });
  const verifyOperationalReviewer=(nowMs)=>buildRoutineApprovalClaim({
    context:routineContext,githubEvidence:verified.proof,
    officialApproval:official,
    codexReceipt:{
      reviewJson:req.reviewJson,
      reviewSignatureBase64:req.reviewSignatureBase64,
      codexReviewerPublicKeyPem:trust.codexReviewerPublicKeyPem,
      issuerReviewerPublicKeyPem:trust.reviewerPublicKeyPem
    },
    reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
    reviewJson:req.routineReviewJson,
    reviewSignatureBase64:req.routineReviewSignatureBase64,
    nowMs
  });
  verifyOperationalReviewer(Date.now());
  const prior=inspectProtectedCurrentSnapshot(ROOT);
  if(prior.commit===req.head||prior.commit===null)deny();
  const previousHashes=hashes(prior.files);
  const futureHashes=hashes(verified.approved.manifest.files);
  let finalNowMs;
  return await withProtectedOperationGuard(ROOT,async()=>{
    // From this point, crashes and UNKNOWN outcomes preserve the lock;
    // no automatic replay or stale-lock removal is permitted.
    const outcome=await applyProtectedUpdateCandidate({
      root:ROOT,stateDir:STATE,
      manifestJson:req.manifestJson,approvalJson:req.approvalJson,
      signatureBase64:req.signatureBase64,
      pinnedPublicKey:trust.approvalPublicKeyPem,
      proof:verified.proof,contents:verified.contents,
      oldFiles:prior.files,operationId:req.operationId,nowMs:finalNowMs,
      observeHealth:async()=>{
        assertPinnedProtectedLauncher(ROOT,launcherHash);
        return observeProtectedWorkerHealth({
          pinnedWorkerUid:uid,pinnedWorkerGid:gid,
          expectedCommit:req.head,expectedHashes:futureHashes
        });
      }
    });
    if(!['verified','rolled_back'].includes(outcome?.phase))deny();
    return Object.freeze({
      state:outcome.phase,operationId:req.operationId,
      commit:outcome.commit,safeToReplay:false
    });
  },{verifyReadOnly:()=>{
    // The emergency restore uses this same durable lock; never accept a
    // baseline captured before restoration or an unexpected pointer change.
    assertPinnedProtectedLauncher(ROOT,launcherHash);
    const current=inspectProtectedCurrentSnapshot(ROOT);
    if(current.commit!==prior.commit||
       JSON.stringify(hashes(current.files))!==
         JSON.stringify(previousHashes))deny();
    // A confirmed unhealthy baseline is a READ-ONLY rejection, not an
    // interrupted update; the lock may be durably released in this phase.
    if(observeProtectedWorkerHealth({
      pinnedWorkerUid:uid,pinnedWorkerGid:gid,
      expectedCommit:prior.commit,expectedHashes:previousHashes
    })!==true)deny();
    finalNowMs=Date.now();
    verifyOperationalReviewer(finalNowMs);
    verifySignedProtectedUpdateApproval({
      manifestJson:req.manifestJson,approvalJson:req.approvalJson,
      signatureBase64:req.signatureBase64,
      trustPublicKeyPem:trust.approvalPublicKeyPem,
      trustedHead:req.head,trustedBase:req.base,
      trustedOperationId:req.operationId,nowMs:finalNowMs
    });
    verifyIndependentSignedReview({
      reviewJson:req.reviewJson,
      signatureBase64:req.reviewSignatureBase64,
      pinnedReviewerPublicKeyPem:trust.codexReviewerPublicKeyPem,
      pinnedApprovalPublicKeyPem:trust.approvalPublicKeyPem,
      head:req.head,base:req.base,prNumber:req.prNumber,
      nowMs:finalNowMs
    });
    // Duplicate operation IDs, stale journals, old staged releases and
    // no-op updates are rejected BEFORE entry to mutation/UNKNOWN state.
    const admission=preflightProtectedUpdateAdmission({
      root:ROOT,stateDir:STATE,manifestJson:req.manifestJson,
      approvalJson:req.approvalJson,signatureBase64:req.signatureBase64,
      pinnedPublicKey:trust.approvalPublicKeyPem,
      proof:verified.proof,operationId:req.operationId,nowMs:finalNowMs,
      contents:verified.contents,oldFiles:prior.files
    });
    if(admission.state!=='read_only_transaction_admitted')deny();
    return true;
  }});
}
// Importing from nonroot unit tests is inert; direct source-checkout
// invocation MUST fail without touching the running protected controller.
if(process.argv[1]&&fileURLToPath(import.meta.url)===
    resolve(process.argv[1])){
  try{
    const outcome=await applyOneProtectedUpdateFixedRoot();
    process.stdout.write(JSON.stringify(outcome)+'\n');
  }catch{
    process.stderr.write('protected_root_apply_denied_or_unknown\n');
    process.exitCode=1;
  }
}
