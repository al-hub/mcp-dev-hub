// #35 UNINSTALLED fixed-root one-shot issuer orchestration candidate.
// One owner-authorized root session must first stage a pinned source package,
// root-only evidence, two physically isolated role keypairs, scope-reduced
// GitHub read tokens and the root-owned 6-file issuer runtime. This command
// NEVER installs sudoers, changes the running controller, or retries unknown
// signer/HTTPS outcomes. Its outputs are root-only reviewed attestations.
// Worker cannot invoke arbitrary commands, signers, keys or payloads.
import {createHash,createPublicKey} from 'node:crypto';
import {constants,closeSync,fstatSync,fsyncSync,lstatSync,openSync,
  readFileSync,writeSync,fchmodSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {selectFixedIssuerSourceRows}
  from './protected-update-issuer-stage.mjs';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';
import {readRootProtectedUpdateTrust}
  from '../src/ops/protected-update-root-evidence.mjs';
import {parsePinnedBootstrapIssuerContext,
  buildBootstrapApprovalClaim}
  from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {fetchAndVerifyGitHubBootstrapEvidence,
  fetchAndVerifyOfficialReviewerApproval}
  from '../src/ops/protected-update-github-evidence.mjs';
import {verifyProtectedBootstrapAttestations}
  from '../src/ops/protected-update-install-attestation.mjs';
import {readFixedIndependentCodexReceipt}
  from '../src/ops/protected-update-issuer-runtime.mjs';
import {stageFixedRoutineOperation}
  from '../src/ops/protected-update-routine-stage.mjs';
import {assembleCollectedRoutineAuthorization}
  from '../src/ops/protected-update-routine-collection.mjs';
import {parseProtectedRoutineIntent}
  from '../src/ops/protected-update-routine-intent.mjs';
import {buildRoutineApprovalClaim}
  from '../src/ops/protected-update-routine-issuer.mjs';
import {verifyAppAcceptanceReviewer,verifySignedAppAcceptance}
  from '../src/ops/protected-update-app-acceptance.mjs';
import {validateReviewEvidence,validateProtectionEvidence}
  from '../src/jobs/github-app-review-publisher.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-issuer-collect.mjs';
const ROOT_APPLY=PACK+'/code/scripts/protected-update-root-apply.mjs';
const CODE=ROOT+'/protected-issuer/code';
const BASE='/var/lib/mcp-dev-hub-signers';
const TRUST='/etc/mcp-dev-hub/protected-update';
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;
const HASH=/^[a-f0-9]{64}$/;
const deny=()=>{throw Error('protected_issuer_collect_denied_or_unknown');};
const digest=b=>createHash('sha256').update(b).digest('hex');
function dir(path,owner=0,mode=null){
  const s=lstatSync(path);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
     (s.mode&0o022)!==0||
     (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function readOwned(path,owner,mode,maxBytes){
  const fd=openSync(path,READ);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==owner||s.nlink!==1||
       (s.mode&0o777)!==mode||s.size<1||s.size>maxBytes)deny();
    const b=readFileSync(fd);
    if(b.length!==s.size)deny();
    return b.toString('utf8');
  }finally{closeSync(fd);}
}
function absent(path){
  try{lstatSync(path);deny();}catch(e){
    if(e.code!=='ENOENT')throw e;
  }
}
function writeRoot(path,text,mode){
  const bytes=Buffer.from(text,'utf8');
  if(bytes.length<1||bytes.length>16000)deny();
  const fd=openSync(path,WRITE,0o600);
  try{
    let n=0;
    while(n<bytes.length){
      const w=writeSync(fd,bytes,n,bytes.length-n,n);
      if(w<=0)deny();
      n+=w;
    }
    fchmodSync(fd,mode);
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==mode||s.size!==bytes.length)deny();
  }finally{closeSync(fd);}
  // The file's directory entry must survive a crash before the next
  // irreversible role dispatch; fsync(file) alone is insufficient.
  const parentFd=openSync(dirname(path),constants.O_RDONLY|
    constants.O_NOFOLLOW|constants.O_DIRECTORY);
  try{fsyncSync(parentFd);}finally{closeSync(parentFd);}
}
function ownerNumber(file){
  const raw=readOwned(TRUST+'/'+file,0,0o400,32).trim();
  if(!/^[1-9][0-9]{0,8}$/.test(raw))deny();
  return Number(raw);
}
function rootString(file,max=4096){
  return readOwned(TRUST+'/'+file,0,0o400,max).trim();
}
function assertInstalledRuntime(rows){
  const names=['/','/usr','/usr/local','/usr/local/lib',ROOT,
    ROOT+'/protected-issuer',CODE,CODE+'/scripts',
    CODE+'/src',CODE+'/src/ops'];
  for(const path of names)dir(path,0);
  for(const row of rows){
    const text=readOwned(CODE+'/'+row.path,0,0o444,
      row.bytes);
    if(Buffer.byteLength(text,'utf8')!==row.bytes||
       digest(Buffer.from(text,'utf8'))!==row.sha256)deny();
  }
}
function parseSignedOutput(raw,keys){
  if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>5000)deny();
  let o;
  try{o=JSON.parse(raw.trim());}catch{deny();}
  if(!o||Array.isArray(o)||typeof o!=='object'||
     Object.keys(o).sort().join(',')!==keys.slice().sort().join(',')||
     keys.some(k=>typeof o[k]!=='string'))deny();
  return o;
}
function runRole(name,role,operationId=null){
  const uid=ownerNumber(role+'-uid'),gid=ownerNumber(role+'-gid');
  const path=CODE+'/scripts/'+name;
  const r=spawnSync('/usr/bin/node',[path],{
    uid,gid,cwd:'/',shell:false,encoding:'utf8',timeout:60000,
    maxBuffer:5000,stdio:['ignore','pipe','pipe'],
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',HOME:'/',
      ...(operationId===null?{}:{MCP_PROTECTED_OPERATION_ID:operationId})}
  });
  if(r.error||r.signal||r.status!==0||
     typeof r.stdout!=='string'||r.stdout.length>5000)deny();
  return r.stdout;
}
function verifyRootContext(context,pack){
  const expectedBase=rootString('approved-base-commit',128);
  const expectedCommit=rootString('baseline-commit',128);
  const expectedRun=Number(rootString('approved-ci-run-id',48));
  const expectedPr=Number(rootString('approved-pr-number',48));
  const expectedBot=Number(rootString('reviewer-bot-id',48));
  const original=rootString('baseline-files.json');
  if(pack.head!==context.head||
     context.packDigest!==pack.manifestSha256||
     context.base!==expectedBase||
     context.baselineCommit!==expectedCommit||
     context.prNumber!==expectedPr||
     context.ciRunId!==expectedRun||
     context.reviewerBotId!==expectedBot||
     context.baselineDigest!==digest(Buffer.from(original,'utf8')))
    deny();
}
/** Pure, non-authoritative root collector response bound to BOTH signatures,
 * trusted original context and latest root-verified official GitHub evidence.
 */
export function verifyCollectedBootstrapSignatures({
  context,review,approval,rootTrust,nowMs
}={}){
  if(!context||!review||!approval||!rootTrust||
     !Number.isSafeInteger(nowMs)||nowMs<=0)deny();
  const status=verifyProtectedBootstrapAttestations({
    reviewJson:review.reviewJson,
    reviewSignatureBase64:review.reviewSignatureBase64,
    approvalJson:approval.approvalJson,
    approvalSignatureBase64:approval.approvalSignatureBase64,
    reviewerPublicKeyPem:rootTrust.reviewerPublicKeyPem,
    approvalPublicKeyPem:rootTrust.approvalPublicKeyPem,
    head:context.head,base:context.base,
    packDigest:context.packDigest,
    baselineCommit:context.baselineCommit,
    baselineDigest:context.baselineDigest,
    prNumber:context.prNumber,ciRunId:context.ciRunId,nowMs
  });
  if(status.safeToInstall!==false)deny();
  return Object.freeze({state:'two_sigs_bound_needs_owner_bootstrap',
    reviewRunId:status.reviewRunId,safeToInstall:false});
}
export async function collectFixedBootstrapIssuerAttestations(){
  if(process.getuid?.()!==0||process.geteuid?.()!==0||
     fileURLToPath(import.meta.url)!==ENTRY||process.argv.length!==2)
    deny();
  for(const path of [
    '/','/usr','/usr/local','/usr/local/lib',ROOT,
    PACK,PACK+'/code','/etc','/etc/mcp-dev-hub',TRUST,
    '/var','/var/lib',BASE
  ])dir(path,0);
  dir(BASE+'/issuer-reviewer',ownerNumber('reviewer-uid'),0o700);
  dir(BASE+'/issuer-approval',ownerNumber('approval-uid'),0o700);
  assertFixedOperationalIssuerIsolation();
  const pinned=rootString('approved-pack-digest',128);
  if(!HASH.test(pinned))deny();
  const pack=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:pinned
  });
  if(pack.status!=='source_only_unprivileged_no_go')deny();
  const rows=selectFixedIssuerSourceRows(pack.files);
  assertInstalledRuntime(rows);
  const context=parsePinnedBootstrapIssuerContext(readOwned(
    BASE+'/approved-bootstrap-context.json',0,0o444,2048
  ));
  verifyRootContext(context,pack);
  const trust=readRootProtectedUpdateTrust();
  for(const file of [
    BASE+'/review-handoff.json',
    TRUST+'/bootstrap-review.json',TRUST+'/bootstrap-review.sig',
    TRUST+'/bootstrap-approval.json',TRUST+'/bootstrap-approval.sig'
  ])absent(file);
  // The root supervisor independently verifies the same CI/Bot evidence;
  // neither signing principal can supply or override these results.
  const [gh,official]=await Promise.all([
    fetchAndVerifyGitHubBootstrapEvidence({
      prNumber:context.prNumber,head:context.head,base:context.base,
      ciRunId:context.ciRunId,githubToken:trust.githubToken
    }),
    fetchAndVerifyOfficialReviewerApproval({
      prNumber:context.prNumber,head:context.head,
      reviewerBotId:context.reviewerBotId,
      githubToken:trust.githubToken,nowMs:Date.now()
    })
  ]);
  if(official.reviewActor!==context.reviewerBotActor||
     !official.reviewEvidenceId)deny();
  if(typeof process.setgroups!=='function')deny();
  process.setgroups([]);
  const review=parseSignedOutput(runRole(
    'protected-update-review-issuer.mjs','reviewer'
  ),['reviewJson','reviewSignatureBase64']);
  // Independently verify signature and scope before root-owned handoff.
  buildBootstrapApprovalClaim({
    context,githubEvidence:gh,officialApproval:official,
    reviewerPublicKeyPem:trust.reviewerPublicKeyPem,
    codexReceipt:readFixedIndependentCodexReceipt(),
    ...review,nowMs:Date.now()
  });
  writeRoot(BASE+'/review-handoff.json',JSON.stringify(review),0o444);
  const approval=parseSignedOutput(runRole(
    'protected-update-approval-issuer.mjs','approval'
  ),['approvalJson','approvalSignatureBase64']);
  const verified=verifyCollectedBootstrapSignatures({
    context,review,approval,rootTrust:trust,nowMs:Date.now()
  });
  writeRoot(TRUST+'/bootstrap-review.json',review.reviewJson,0o400);
  writeRoot(TRUST+'/bootstrap-review.sig',review.reviewSignatureBase64,0o400);
  writeRoot(TRUST+'/bootstrap-approval.json',approval.approvalJson,0o400);
  writeRoot(TRUST+'/bootstrap-approval.sig',approval.approvalSignatureBase64,
    0o400);
  return Object.freeze({state:'attestations_pinned_pending_owner_activation',
    reviewRunId:verified.reviewRunId,
    realProtectedUpdates:0,safeToRetry:false});
}
/** Bound routine signer orchestration inside the existing fixed root-apply
 * executable. Caller can only supply a canonical untrusted DATA intent.
 * Root independently pins keys, GitHub CI/Bot, source pack and controller
 * bytes BEFORE creating the immutable, one-use operation slot. No arbitrary
 * argv, role script, sudo command, path or private key is accepted.
 */
export async function collectFixedRoutineIssuerAttestations({intent}={}){
  if(process.getuid?.()!==0||process.geteuid?.()!==0||
     process.argv.length!==2||
     fileURLToPath(import.meta.url)!==ENTRY||
     ![ENTRY,ROOT_APPLY].includes(resolve(process.argv[1])))deny();
  const x=parseProtectedRoutineIntent(JSON.stringify(intent));
  for(const path of [
    '/','/usr','/usr/local','/usr/local/lib',ROOT,
    PACK,PACK+'/code','/etc','/etc/mcp-dev-hub',TRUST,
    '/var','/var/lib',BASE
  ])dir(path,0);
  assertFixedOperationalIssuerIsolation();
  const trust=readRootProtectedUpdateTrust();
  const pinned=rootString('approved-pack-digest',128);
  if(!HASH.test(pinned)||trust.approvedPackDigest!==pinned)deny();
  const pack=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:pinned
  });
  if(pack.status!=='source_only_unprivileged_no_go')deny();
  assertInstalledRuntime(selectFixedIssuerSourceRows(pack.files));
  const context={
    version:1,repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
    head:x.head,base:x.base,prNumber:x.prNumber,ciRunId:x.ciRunId,
    reviewerBotId:ownerNumber('reviewer-bot-id'),
    reviewerBotActor:'mcp-dev-hub-ai-reviewer[bot]',
    operationId:x.operationId,manifestJson:x.manifestJson,
    packDigest:pinned
  };
  const codexReceipt={
    reviewJson:x.reviewJson,
    reviewSignatureBase64:x.reviewSignatureBase64,
    codexReviewerPublicKeyPem:trust.codexReviewerPublicKeyPem,
    issuerReviewerPublicKeyPem:trust.reviewerPublicKeyPem
  };
  // The operation directory is a non-replayable durable attempt fence.
  // Even a partial directory means UNKNOWN and is never erased/retried.
  const staged=await stageFixedRoutineOperation({
    context,codexReceipt
  });
  const slot=BASE+'/routine-operations/'+x.operationId;
  const review=parseSignedOutput(runRole(
    'protected-update-routine-review-issuer.mjs',
    'reviewer',x.operationId
  ),['reviewJson','reviewSignatureBase64']);
  // Independently authenticate the review before exposing its canonical
  // handoff to the approval role. Unlike a CLI exit, this verifies Ed25519.
  buildRoutineApprovalClaim({
    context,githubEvidence:staged.githubEvidence,
    officialApproval:staged.officialApproval,codexReceipt,
    reviewerPublicKeyPem:trust.reviewerPublicKeyPem,...review,
    nowMs:Date.now()
  });
  writeRoot(slot+'/routine-review-handoff.json',JSON.stringify(review),0o444);
  const approval=parseSignedOutput(runRole(
    'protected-update-routine-approval-issuer.mjs',
    'approval',x.operationId
  ),['approvalJson','approvalSignatureBase64']);
  // A second root-side live cross-check prevents a stale earlier evidence
  // snapshot from being silently promoted by a later signing result.
  const [gh,official]=await Promise.all([
    fetchAndVerifyGitHubBootstrapEvidence({
      prNumber:context.prNumber,head:context.head,base:context.base,
      ciRunId:context.ciRunId,githubToken:trust.githubToken
    }),
    fetchAndVerifyOfficialReviewerApproval({
      prNumber:context.prNumber,head:context.head,
      reviewerBotId:context.reviewerBotId,
      githubToken:trust.githubToken,nowMs:Date.now()
    })
  ]);
  const result=assembleCollectedRoutineAuthorization({
    context,githubEvidence:gh,officialApproval:official,codexReceipt,
    review,approval,rootTrust:trust,nowMs:Date.now()
  });
  writeRoot(slot+'/routine-approval.json',approval.approvalJson,0o444);
  writeRoot(slot+'/routine-approval.sig',approval.approvalSignatureBase64,
    0o444);
  writeRoot(slot+'/approved-request.json',result.requestJson,0o400);
  writeRoot(slot+'/issuance-complete.json',JSON.stringify({
    version:1,operationId:x.operationId,
    requestSha256:digest(Buffer.from(result.requestJson,'utf8')),
    phase:'both_signed_pending_root_apply',safeToReplay:false
  }),0o400);
  return Object.freeze({
    status:'signed_routine_request_pending_root_guard',
    operationId:x.operationId,requestJson:result.requestJson,
    safeToReplay:false
  });
}
// An optional root-pinned, single-purpose dispatch mode reuses the SAME
// fixed collector entrypoint. No caller flags, environment modes, or added
// privileged command. Absent mode retains the existing bootstrap behavior.
function fixedRootCollectorMode(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    fileURLToPath(import.meta.url)!==ENTRY||
    process.argv.length!==2||resolve(process.argv[1])!==ENTRY)deny();
 for(const path of ['/','/etc','/etc/mcp-dev-hub',TRUST])dir(path,0);
 const file=TRUST+'/app-acceptance-collector-mode';
 try{lstatSync(file);}catch(e){
  if(e.code==='ENOENT')return 'bootstrap';
  throw e;
 }
 if(readOwned(file,0,0o400,48).trim()!=='app-acceptance')deny();
 return 'app-acceptance';
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const mode=fixedRootCollectorMode();
  const result=mode==='app-acceptance'
    ?await collectFixedAppAcceptanceAttestations()
    :await collectFixedBootstrapIssuerAttestations();
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch{
  process.stderr.write('protected_issuer_collect_denied_or_unknown\n');
  process.exitCode=1;
 }
}


// Source-only fixed root collection of a **previously authenticated**
// independent reviewer handoff. This cannot create reviewer evidence,
// produce missing acceptance gates, install an issuer, or post GitHub reviews.
// It will fail before creating an attempt if there is no genuine reviewer
// signature and final-HEAD Codex receipt. A one-use fsynced intent is retained
// on uncertain signer, network or filesystem outcomes; no automatic replay.
export async function collectFixedAppAcceptanceAttestations(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    fileURLToPath(import.meta.url)!==ENTRY||
    process.argv.length!==2||resolve(process.argv[1])!==ENTRY)deny();
 for(const path of [
  '/','/usr','/usr/local','/usr/local/lib',ROOT,
  PACK,PACK+'/code','/etc','/etc/mcp-dev-hub',TRUST,
  '/var','/var/lib',BASE
 ])dir(path,0);
 assertFixedOperationalIssuerIsolation();
 const pinned=rootString('approved-pack-digest',128);
 if(!HASH.test(pinned))deny();
 const pack=verifyProtectedBootstrapPack({
  outputPath:PACK,expectedManifestSha256:pinned
 });
 if(pack.status!=='source_only_unprivileged_no_go')deny();
 assertInstalledRuntime(selectFixedIssuerSourceRows(pack.files));
 const context=parsePinnedBootstrapIssuerContext(readOwned(
  BASE+'/approved-bootstrap-context.json',0,0o444,2048
 ));
 verifyRootContext(context,pack);
 const trust=readRootProtectedUpdateTrust();
 const raw=readOwned(BASE+'/app-acceptance.json',0,0o444,12000);
 const reviewerSignature=readOwned(
  BASE+'/app-acceptance.review.sig',0,0o444,256
 ).trim();
 const codexReceipt=readFixedIndependentCodexReceipt();
 const der=k=>createPublicKey(k).export({type:'spki',format:'der'});
 if(trust.approvedPackDigest!==pinned||
    !der(codexReceipt.codexReviewerPublicKeyPem)
      .equals(der(trust.codexReviewerPublicKeyPem))||
    !der(codexReceipt.issuerReviewerPublicKeyPem)
      .equals(der(trust.reviewerPublicKeyPem)))deny();
 const handoff={
  raw,reviewSignatureBase64:reviewerSignature,
  pinnedReviewerPublicKeyPem:trust.reviewerPublicKeyPem,
  head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:pinned,nowMs:Date.now()
 };
 const reviewer=verifyAppAcceptanceReviewer(handoff);
 const packet=reviewer.packet;
 if(packet.issuedAtMs<1)deny();
 const source={
  prNumber:39,headSha:context.head,baseSha:context.base,
  packDigest:pinned,evidence:packet.evidence,
  verifyEvidence:()=>true,
  protectionEvidence:packet.protectionEvidence,
  verifyProtectionEvidence:()=>true,
  signedCodexReceipt:{
   reviewJson:codexReceipt.reviewJson,
   signatureBase64:codexReceipt.reviewSignatureBase64
  },
  pinnedCodexPublicKeyPem:trust.codexReviewerPublicKeyPem,
  pinnedIssuerReviewerPublicKeyPem:trust.reviewerPublicKeyPem
 };
 // Both claims are cryptographically bound to the independently operated
 // reviewer key. Root trust of physical PC/Galaxy/private-SSE results is a
 // SEPARATE obligation for the reviewer producer, not a JSON assertion.
 validateReviewEvidence(source);
 validateProtectionEvidence(source);
 await fetchAndVerifyGitHubBootstrapEvidence({
  prNumber:39,head:context.head,base:context.base,
  ciRunId:context.ciRunId,githubToken:trust.githubToken
 });
 const files=[
  'app-acceptance-dispatch.intent.json','app-acceptance.json',
  'app-acceptance.review.sig','app-acceptance.sig',
  'app-acceptance.sha256'
 ];
 for(const name of files)absent(TRUST+'/'+name);
 // The durable fence precedes ANY external approval-role dispatch. A
 // post-intent failure stays UNKNOWN until separate trusted reconciliation.
 writeRoot(TRUST+'/app-acceptance-dispatch.intent.json',JSON.stringify({
  version:1,head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:pinned,
  packetSha256:reviewer.packetSha256,
  state:'issuer_dispatched_or_unknown',safeToReplay:false
 }),0o400);
 const output=runRole(
  'protected-update-app-acceptance-approval-issuer.mjs','approval'
 );
 let signed;
 try{signed=JSON.parse(output.trim());}catch{deny();}
 if(!signed||Array.isArray(signed)||typeof signed!=='object'||
    Object.keys(signed).sort().join(',')!==
      'packetSha256,safeToInstall,safeToReplay,signatureBase64'||
    signed.packetSha256!==reviewer.packetSha256||
    signed.safeToInstall!==false||signed.safeToReplay!==false||
    typeof signed.signatureBase64!=='string')deny();
 verifySignedAppAcceptance({
  ...handoff,signatureBase64:signed.signatureBase64,
  pinnedApprovalPublicKeyPem:trust.approvalPublicKeyPem,
  nowMs:Date.now()
 });
 // After the role check, refetch the protected PR and exact CI again.
 await fetchAndVerifyGitHubBootstrapEvidence({
  prNumber:39,head:context.head,base:context.base,
  ciRunId:context.ciRunId,githubToken:trust.githubToken
 });
 verifySignedAppAcceptance({
  ...handoff,signatureBase64:signed.signatureBase64,
  pinnedApprovalPublicKeyPem:trust.approvalPublicKeyPem,
  nowMs:Date.now()
 });
 // Never overwrite. Partial files and intent remain for trusted readback.
 writeRoot(TRUST+'/app-acceptance.json',raw,0o400);
 writeRoot(TRUST+'/app-acceptance.review.sig',reviewerSignature,0o400);
 writeRoot(TRUST+'/app-acceptance.sig',signed.signatureBase64,0o400);
 writeRoot(TRUST+'/app-acceptance.sha256',
  reviewer.packetSha256,0o400);
 return Object.freeze({
  state:'dual_signatures_collected_pending_app_live_readback',
  head:context.head,safeToReplay:false,
  approvalPosted:false,installerAuthorized:false
 });
}
