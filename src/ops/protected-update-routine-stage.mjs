// #35 root-authenticated source candidate: per-operation immutable handoff.
// This is neither an installed privilege path nor independent approval.
// No unattended replay on interrupted staging or missing role signatures.
import {createHash,createPublicKey} from 'node:crypto';
import {constants,closeSync,fchmodSync,fstatSync,fsyncSync,lstatSync,
  mkdirSync,openSync,writeSync,chmodSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {parsePinnedRoutineIssuerContext,buildRoutineReviewerClaim}
  from './protected-update-routine-issuer.mjs';
import {validateProposedProtectedUpdate}
  from './protected-update-manifest.mjs';
import {readRootProtectedUpdateTrust}
  from './protected-update-root-evidence.mjs';
import {assertFixedOperationalIssuerIsolation}
  from './protected-update-issuer-boundary.mjs';
import {fetchAndVerifyGitHubBootstrapEvidence,
  fetchAndVerifyOfficialReviewerApproval,fetchAndVerifyGitHubControllerPair}
  from './protected-update-github-evidence.mjs';
import {verifyProtectedBootstrapPack}
  from '../../scripts/protected-update-bootstrap-pack.mjs';
import {acquireRoutineDispatchFence,probeDifferentInstalledPair}
  from './protected-update-routine-dispatch-fence.mjs';
import {inspectProtectedCurrentSnapshot}
  from './protected-update-release-pointer.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const BASE='/var/lib/mcp-dev-hub-signers';
const OPS=BASE+'/routine-operations';
const ENTRY=ROOT+'/protected-updater/code/scripts/protected-update-root-apply.mjs';
const ROOT_COLLECT=ROOT+'/protected-updater/code/scripts/protected-update-issuer-collect.mjs';
const deny=()=>{throw Error('protected_routine_stage_denied_or_unknown');};
const sha=s=>createHash('sha256').update(s).digest('hex');
function pub(pem){
 let k;try{k=createPublicKey(pem);}catch{deny();}
 if(k.asymmetricKeyType!=='ed25519')deny();
 return k.export({type:'spki',format:'der'});
}
function safeDirectory(path,mode=null){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||
    (s.mode&0o022)!==0||
    (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function fsyncDirectory(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|
   constants.O_DIRECTORY);
 try{fsyncSync(fd);}finally{closeSync(fd);}
}
function writeOnce(path,value,mode=0o444){
 const b=Buffer.from(value,'utf8');
 if(b.length<1||b.length>7000)deny();
 const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|
   constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{
  let offset=0;
  while(offset<b.length){
   const n=writeSync(fd,b,offset,b.length-offset,offset);
   if(n<=0)deny();offset+=n;
  }
  fchmodSync(fd,mode);fsyncSync(fd);
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
     (s.mode&0o777)!==mode||s.size!==b.length)deny();
 }finally{closeSync(fd);}
}
/** Pure cryptographic binding check, not trusted-origin verification.
 * Production obtains live GitHub and pinned OS trust inside the root entry.
 */
export function verifyRoutineStageInputs({
 context,codexReceipt,rootTrust,githubEvidence,officialApproval,nowMs
}={}){
 const c=parsePinnedRoutineIssuerContext(JSON.stringify(context));
 if(!rootTrust||typeof rootTrust!=='object'||
    !codexReceipt||typeof codexReceipt!=='object'||
    c.packDigest!==rootTrust.approvedPackDigest)deny();
 const r=pub(rootTrust.reviewerPublicKeyPem);
 const x=pub(rootTrust.codexReviewerPublicKeyPem);
 const a=pub(rootTrust.approvalPublicKeyPem);
 if(r.equals(x)||r.equals(a)||x.equals(a)||
    !r.equals(pub(codexReceipt.issuerReviewerPublicKeyPem))||
    !x.equals(pub(codexReceipt.codexReviewerPublicKeyPem)))deny();
 buildRoutineReviewerClaim({
  context:c,githubEvidence,officialApproval,codexReceipt,nowMs
 });
 return Object.freeze({
   operationId:c.operationId,head:c.head,
   manifestSha256:sha(c.manifestJson),
   sourceOnly:true,installerAuthorized:false
 });
}
/** Sole fixed root-owned entry can stage sealed evidence for one operation.
 * Stage data is public-key/canonical claim material ONLY, never a private
 * signing key, Github token or process environment from the Worker.
 * Slot existence is a non-replayable UNKNOWN fence, including partial writes.
 */
export async function stageFixedRoutineOperation({
 context,codexReceipt
}={}){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    process.argv.length!==2||
    ![ENTRY,ROOT_COLLECT].includes(fileURLToPath(
      new URL('file://'+process.argv[1]))))deny();
 for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
   ROOT+'/protected-updater','/var','/var/lib',BASE])safeDirectory(p);
 assertFixedOperationalIssuerIsolation();
 const trust=readRootProtectedUpdateTrust();
 const c=parsePinnedRoutineIssuerContext(JSON.stringify(context));
 if(c.packDigest!==trust.approvedPackDigest)deny();
 const pack=verifyProtectedBootstrapPack({
  outputPath:ROOT+'/protected-updater',
  expectedManifestSha256:trust.approvedPackDigest
 });
 if(pack.status!=='source_only_unprivileged_no_go')deny();
 const manifest=validateProposedProtectedUpdate(c.manifestJson,{
  verifiedCommit:c.head
 });
 const [gh,bot]=await Promise.all([
  fetchAndVerifyGitHubBootstrapEvidence({
   prNumber:c.prNumber,head:c.head,base:c.base,ciRunId:c.ciRunId,
   githubToken:trust.githubToken
  }),
  fetchAndVerifyOfficialReviewerApproval({
   prNumber:c.prNumber,head:c.head,
   reviewerBotId:c.reviewerBotId,githubToken:trust.githubToken,
   nowMs:Date.now()
  }),
  fetchAndVerifyGitHubControllerPair({
   head:c.head,manifestFiles:manifest.files,
   githubToken:trust.githubToken
  })
 ]).then(([g,b])=>[g,b]);
 verifyRoutineStageInputs({
  context:c,codexReceipt,rootTrust:trust,
  githubEvidence:gh,officialApproval:bot,nowMs:Date.now()
 });
 try{
  safeDirectory(OPS,0o755);
 }catch(e){
  if(e.code!=='ENOENT')throw e;
  mkdirSync(OPS,{mode:0o755});
  safeDirectory(OPS,0o755);fsyncDirectory(BASE);
 }
 // A single crash-durable slot fence serializes all routine signers,
 // including distinct update IDs, before any signer begins.
 acquireRoutineDispatchFence(c.operationId,{validateCandidate:()=>{
  const installed=inspectProtectedCurrentSnapshot(ROOT);
  return probeDifferentInstalledPair({
   installedCommit:installed.commit,requestedHead:c.head,
   installedFiles:installed.files,requestedFiles:manifest.files
  });
 }});
 const slot=OPS+'/'+c.operationId;
 // An earlier attempt, including a partial directory, is UNKNOWN.
 // Never delete, overwrite or start the signers again for this ID.
 mkdirSync(slot,{mode:0o700});
 fsyncDirectory(OPS);
 writeOnce(slot+'/approved-routine-context.json',JSON.stringify(c));
 writeOnce(slot+'/codex-review.json',codexReceipt.reviewJson);
 writeOnce(slot+'/codex-review.sig',codexReceipt.reviewSignatureBase64);
 writeOnce(slot+'/codex-reviewer-public.pem',
  trust.codexReviewerPublicKeyPem);
 writeOnce(slot+'/reviewer-public.pem',trust.reviewerPublicKeyPem);
 writeOnce(slot+'/dispatch.intent.json',JSON.stringify({
   version:1,operationId:c.operationId,head:c.head,
   manifestSha256:sha(c.manifestJson),
   phase:'staged_before_signer_dispatch'
 }));
 fsyncDirectory(slot);
 chmodSync(slot,0o755);
 safeDirectory(slot,0o755);
 fsyncDirectory(OPS);
 return Object.freeze({
  operationId:c.operationId,context:c,codexReceipt,
  githubEvidence:gh,officialApproval:bot,
  state:'staged_once_unknown_until_verified',installerAuthorized:false
 });
}
