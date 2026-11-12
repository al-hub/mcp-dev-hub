// #35: strict no-arguments ONE-SHOT BOOTSTRAP ENTRYPOINT CANDIDATE.
// Never run this from a checkout as root. An independently reviewed OS admin
// bootstrap must first copy a digest-pinned package into its fixed root-owned
// location, pin separate trusted issuers/baseline and review recovery.
// DOES NOT establish signer operational independence or install sudo policy.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';
import {fileURLToPath} from 'node:url';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';

import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {readRootProtectedUpdateTrust}
  from '../src/ops/protected-update-root-evidence.mjs';
import {verifyProtectedBootstrapAttestations}
  from '../src/ops/protected-update-install-attestation.mjs';
import {verifyLocalProtectedBootstrapContract}
  from '../src/ops/protected-update-local-trust-contract.mjs';
import {fetchAndVerifyGitHubBootstrapEvidence,
  fetchAndVerifyOfficialReviewerApproval}
  from '../src/ops/protected-update-github-evidence.mjs';
import {migrateProtectedOriginalPairCandidate}
  from '../src/ops/protected-update-bootstrap-migration.mjs';
import {readFixedIndependentCodexReceipt}
  from '../src/ops/protected-update-issuer-runtime.mjs';
import {verifyIndependentSignedReview}
  from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-bootstrap-entry.mjs';
const TRUST='/etc/mcp-dev-hub/protected-update';
const PACK_DIGEST=TRUST+'/approved-pack-digest';
const BASE_COMMIT=TRUST+'/baseline-commit';
const BASE_FILES=TRUST+'/baseline-files.json';
const WRAPPER=PACK+'/code/scripts/protected-update-controller-wrapper.mjs';
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const NAMES=Object.freeze([
  'ai-github-canary-policy.mjs','ai-github-canary.mjs'
]);
const fail=()=>{throw Error('protected_bootstrap_entry_denied');};
const readFlags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
function dir(path,privateRoot=false){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0||
     (privateRoot&&(st.mode&0o777)!==0o700))fail();
}
function rootFile(path,maxBytes){
  const fd=openSync(path,readFlags);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
       (st.mode&0o777)!==0o400||
       st.size<1||st.size>maxBytes)fail();
    const bytes=readFileSync(fd);
    if(bytes.length!==st.size)fail();
    return bytes.toString('utf8');
  }finally{closeSync(fd);}
}
function parseBaseFiles(raw){
  let value;
  try{value=JSON.parse(raw);}catch{fail();}
  if(JSON.stringify(value)!==raw||!Array.isArray(value)||
     value.length!==2)fail();
  const result=[];
  for(let i=0;i<NAMES.length;i++){
    const f=value[i];
    if(!f||typeof f!=='object'||Array.isArray(f)||
       Object.keys(f).sort().join(',')!=='bytes,name,sha256'||
       f.name!==NAMES[i]||
       !Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>256*1024||
       typeof f.sha256!=='string'||!HASH.test(f.sha256))fail();
    result.push(Object.freeze({...f}));
  }
  return Object.freeze(result);
}
/** As-built root OS read-only checks are done BEFORE any migration effect.
 * Signature issuers are required but operational issuer autonomy remains a
 * separate gate. Caller never supplies paths, SHA, stdin or executable args.
 */
export async function bootstrapOneShotFixedRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
     process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)
    fail();
  for(const path of ['/', '/usr','/usr/local','/usr/local/lib',ROOT,
                      PACK,PACK+'/code',PACK+'/code/scripts'])
    dir(path,path===PACK||path===PACK+'/code'||
      path===PACK+'/code/scripts');
  for(const path of ['/', '/etc','/etc/mcp-dev-hub',TRUST])
    dir(path,path===TRUST);
  const pinned= rootFile(PACK_DIGEST,128).trim();
  const baselineCommit=rootFile(BASE_COMMIT,128).trim();
  const expectedLegacyFiles=parseBaseFiles(rootFile(BASE_FILES,4096));
  if(!HASH.test(pinned)||!SHA.test(baselineCommit))fail();
  const trust=readRootProtectedUpdateTrust();
  const signerMode=rootFile(TRUST+'/signer-mode',64).trim();
  if(signerMode!=='wsl-local-v1'&&signerMode!=='external-v1')fail();
  const localMode=signerMode==='wsl-local-v1';
  assertFixedOperationalIssuerIsolation();
  const verified=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:pinned
  });
  // The source manifest intentionally says installAuthorized=false:
  // independently pinned, short-lived signed authorization is a separate
  // mandatory gate, never a mutable flag in the package itself.
  if(verified.status!=='source_only_unprivileged_no_go')fail();

  const base=rootFile(TRUST+'/approved-base-commit',128).trim();
  const prRaw=rootFile(TRUST+'/approved-pr-number',48).trim();
  const runRaw=rootFile(TRUST+'/approved-ci-run-id',48).trim();
  if(!SHA.test(base)||!/^[1-9][0-9]{0,14}$/.test(prRaw)||
     !/^[1-9][0-9]{0,14}$/.test(runRaw))fail();
  const prNumber=Number(prRaw),ciRunId=Number(runRaw);
  if(!Number.isSafeInteger(prNumber)||!Number.isSafeInteger(ciRunId))fail();
  const baselineDigest=createHash('sha256').update(
    JSON.stringify(expectedLegacyFiles),'utf8').digest('hex');
  const reviewJson=rootFile(TRUST+'/bootstrap-review.json',2048);
  const reviewSignatureBase64=
    rootFile(TRUST+'/bootstrap-review.sig',256).trim();
  const approvalJson=rootFile(TRUST+'/bootstrap-approval.json',2048);
  const approvalSignatureBase64=
    rootFile(TRUST+'/bootstrap-approval.sig',256).trim();
  const bound=verifyProtectedBootstrapAttestations({
    reviewJson,reviewSignatureBase64,approvalJson,
    approvalSignatureBase64,
    reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
    approvalPublicKeyPem:trust.approvalPublicKeyPem,
    head:verified.head,base,packDigest:pinned,
    baselineCommit,baselineDigest,prNumber,ciRunId,nowMs:Date.now()
  });
  if(bound.state!=='attestation_bound_not_os_authorized'||
     bound.safeToInstall!==false)fail();
  // Independent, live HTTPS GitHub cross-check: an approval signature and a
  // Worker-supplied CI claim are never sufficient for root-side installation.
  const gh=await fetchAndVerifyGitHubBootstrapEvidence({
    prNumber,head:verified.head,base,ciRunId,
    githubToken:trust.githubToken
  });
  if(gh.head!==bound.head||gh.base!==bound.base||
     gh.ciRunId!==bound.ciRunId||gh.strictProtection!==true||
     gh.ciPassed!==true)fail();
  if(!localMode){
  const reviewerBotIdRaw=rootFile(TRUST+'/reviewer-bot-id',48).trim();
  if(!/^[1-9][0-9]{0,14}$/.test(reviewerBotIdRaw))fail();
  const review=await fetchAndVerifyOfficialReviewerApproval({
    prNumber,head:verified.head,reviewerBotId:Number(reviewerBotIdRaw),
    githubToken:trust.githubToken,nowMs:Date.now()
  });
  if(review.state!=='official_github_bot_review_confirmed'||
     review.head!==verified.head)fail();
  const codexReceipt=readFixedIndependentCodexReceipt();
  const codex=verifyIndependentSignedReview({
    reviewJson:codexReceipt.reviewJson,
    signatureBase64:codexReceipt.reviewSignatureBase64,
    pinnedReviewerPublicKeyPem:trust.codexReviewerPublicKeyPem,
    pinnedApprovalPublicKeyPem:trust.reviewerPublicKeyPem,
    head:verified.head,base,prNumber,nowMs:Date.now()
  });
  if(review.reviewEvidenceId!==deriveSignedCodexEvidenceId({
    reviewDigest:codex.reviewDigest,packDigest:pinned
  }))fail();
  }else{
    // Root-verified WSL-local path: the two protected issuer signatures
    // and a third independently pinned Codex Ed25519 receipt are required.
    let intent;
    const intentJson=rootFile(TRUST+'/local-bootstrap-dispatch.intent.json',2048);
    try{intent=JSON.parse(intentJson);}catch{fail();}
    const fields=['version','head','base','ciRunId','packDigest',
      'phase','safeToReplay'];
    if(!intent||Array.isArray(intent)||
       Object.keys(intent).length!==fields.length||
       !fields.every(k=>Object.hasOwn(intent,k))||
       JSON.stringify(intent)!==intentJson||
       intent.version!==1||intent.head!==verified.head||
       intent.base!==base||intent.ciRunId!==ciRunId||
       intent.packDigest!==pinned||
       intent.phase!=='reviewer_dispatched_or_unknown'||
       intent.safeToReplay!==false)fail();
    const codexReceipt=readFixedIndependentCodexReceipt();
    const result=verifyLocalProtectedBootstrapContract({
      reviewJson,reviewSignatureBase64,approvalJson,
      approvalSignatureBase64,
      reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
      approvalPublicKeyPem:trust.approvalPublicKeyPem,
      codexReviewJson:codexReceipt.reviewJson,
      codexSignatureBase64:codexReceipt.reviewSignatureBase64,
      codexPublicKeyPem:trust.codexReviewerPublicKeyPem,
      head:verified.head,base,packDigest:pinned,
      baselineCommit,baselineDigest,prNumber,ciRunId,
      nowMs:Date.now(),githubEvidence:gh
    });
    if(result.status!=='local_three_principal_signatures_verified_source_only'||
       result.safeToInstall!==false||result.safeToMerge!==false)fail();
  }
  // No owner approval is implied by the signatures; OS installation remains
  // a separately explicit administrator action. This candidate cannot grant
  // itself sudo access or perform the initial immutable file installation.
  const wrapperRow=verified.files.find(
    row=>row.path==='scripts/protected-update-controller-wrapper.mjs');
  if(!wrapperRow||!HASH.test(wrapperRow.sha256))fail();
  const fd=openSync(WRAPPER,readFlags);
  let wrapperBytes;
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
       (st.mode&0o777)!==0o444||
       st.size!==wrapperRow.bytes||st.size<1||st.size>256*1024)fail();
    wrapperBytes=readFileSync(fd);
    if(wrapperBytes.length!==st.size||createHash('sha256')
      .update(wrapperBytes).digest('hex')!==wrapperRow.sha256)fail();
  }finally{closeSync(fd);}
  // GitHub verification is asynchronous. A signature valid when its HTTPS
  // checks began must never authorize root migration after its expiration.
  // Re-check BOTH independent signatures against the actual clock directly
  // before the first protected backup/OS effect.
  verifyProtectedBootstrapAttestations({
    reviewJson,reviewSignatureBase64,approvalJson,
    approvalSignatureBase64,
    reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
    approvalPublicKeyPem:trust.approvalPublicKeyPem,
    head:verified.head,base,packDigest:pinned,
    baselineCommit,baselineDigest,prNumber,ciRunId,nowMs:Date.now()
  });
  if(localMode){
    // Re-fetch live PR/CI/protection after all asynchronous checks; previous
    // read-only observations and signed receipt windows may become stale.
    const ghFinal=await fetchAndVerifyGitHubBootstrapEvidence({
      prNumber,head:verified.head,base,ciRunId,
      githubToken:trust.githubToken
    });
    const codexReceipt=readFixedIndependentCodexReceipt();
    const fresh=verifyLocalProtectedBootstrapContract({
      reviewJson,reviewSignatureBase64,approvalJson,
      approvalSignatureBase64,
      reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
      approvalPublicKeyPem:trust.approvalPublicKeyPem,
      codexReviewJson:codexReceipt.reviewJson,
      codexSignatureBase64:codexReceipt.reviewSignatureBase64,
      codexPublicKeyPem:trust.codexReviewerPublicKeyPem,
      head:verified.head,base,packDigest:pinned,
      baselineCommit,baselineDigest,prNumber,ciRunId,
      nowMs:Date.now(),githubEvidence:ghFinal
    });
    if(fresh.safeToInstall!==false)fail();
  }
  return migrateProtectedOriginalPairCandidate({
    root:ROOT,baselineCommit,expectedLegacyFiles,
    wrapperBytes,wrapperSha256:wrapperRow.sha256
  });
}
// Direct invocation from a checkout is a hard failure, never a successful
// no-op. Imported modules (e.g. nonroot tests) perform no side effects.
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await bootstrapOneShotFixedRoot();
    process.stdout.write(JSON.stringify({
      phase:result.phase,baselineCommit:result.baselineCommit,
      safeToRetry:false
    })+'\n');
  }catch{
    process.stderr.write('protected_bootstrap_entry_denied\n');
    process.exitCode=1;
  }
}
