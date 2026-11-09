// #35 candidate: fixed nonroot approval-role signer for a pre-Bot App packet.
// UNINSTALLED. A distinct, operational reviewer must first sign authentic
// per-gate provenance; root-staged JSON/digests alone NEVER authorize this.
// The approval role then independently checks Codex, actual original bytes,
// exact GitHub CI/branch policy and the canonical reviewer-signed packet.
// No arbitrary paths, commands, signing payloads, stdin or CLI arguments.
import {createHash} from 'node:crypto';
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
 from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyAppAcceptanceReviewer,APP_ACCEPTANCE_DOMAIN}
 from '../src/ops/protected-update-app-acceptance.mjs';
import {verifyIndependentSignedReview,
 fetchAndVerifyGitHubBootstrapEvidence,
 fetchAndVerifyGitHubControllerPair}
 from '../src/ops/protected-update-github-evidence.mjs';
import {deriveSignedCodexEvidenceId}
 from '../src/ops/protected-update-bootstrap-issuer.mjs';
import {assertRoleRuntimeInstalled,readFixedIssuerContext,
 readFixedAppAcceptanceReviewerHandoff,readFixedIssuerToken,
 readFixedIndependentCodexReceipt,signFixedRolePayload}
 from '../src/ops/protected-update-issuer-runtime.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const ENTRY=ROOT+'/protected-issuer/code/scripts/'+
 'protected-update-app-acceptance-approval-issuer.mjs';
const NAMES=['ai-github-canary-policy.mjs','ai-github-canary.mjs'];
const GATES=['ci','security','private_sse','pc','galaxy',
 'root_security'];
const deny=()=>{throw Error('protected_app_acceptance_issuer_denied');};
const hash=b=>createHash('sha256').update(b).digest('hex');
function physicalOriginal(){
 for(const path of ['/','/usr','/usr/local','/usr/local/lib',ROOT]){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0)deny();
 }
 const files=[];
 for(const name of NAMES){
  const path=ROOT+'/'+name,prior=lstatSync(path);
  if(!prior.isFile()||prior.isSymbolicLink()||prior.uid!==0||
     prior.nlink!==1||(prior.mode&0o777)!==0o555||
     prior.size<1||prior.size>256*1024)deny();
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|
    constants.O_NONBLOCK);
  try{
   const st=fstatSync(fd),raw=readFileSync(fd),after=fstatSync(fd);
   if(!st.isFile()||st.ino!==prior.ino||st.dev!==prior.dev||
      st.size!==prior.size||raw.length!==st.size||
      after.ino!==st.ino||after.dev!==st.dev||
      after.size!==st.size||after.mtimeMs!==st.mtimeMs)deny();
   files.push({name,bytes:raw.length,sha256:hash(raw),
    device:st.dev,inode:st.ino,mtimeMs:st.mtimeMs});
  }finally{closeSync(fd);}
 }
 return files;
}
/** Defend original-file TOCTOU across network fetches. The latest root
 * physical snapshot MUST equal the authenticated prior snapshot immediately
 * before signing. A file replacement with identical bytes is also rejected.
 * This remains a pure check; neither snapshot creates authority on its own.
 */
export function verifyUnchangedPhysicalOriginal(before,after){
 if(!Array.isArray(before)||!Array.isArray(after)||
    before.length!==NAMES.length||after.length!==NAMES.length)deny();
 for(let i=0;i<NAMES.length;i++){
  const a=before[i],b=after[i];
  if(!a||!b||a.name!==NAMES[i]||b.name!==NAMES[i]||
     !Number.isSafeInteger(a.bytes)||a.bytes<1||a.bytes>256*1024||
     a.bytes!==b.bytes||
     !/^[a-f0-9]{64}$/.test(a.sha256||'')||
     a.sha256!==b.sha256||
     !Number.isSafeInteger(a.device)||a.device<0||
     !Number.isSafeInteger(a.inode)||a.inode<=0||
     a.device!==b.device||a.inode!==b.inode||
     !Number.isFinite(a.mtimeMs)||a.mtimeMs<0||
     a.mtimeMs!==b.mtimeMs)deny();
 }
 return true;
}
function validateLiveAcceptanceGates(p,context,codex,nowMs){
 if(p.head!==context.head||p.base!==context.base||
    p.ciRunId!==context.ciRunId||p.packDigest!==context.packDigest||
    p.prNumber!==39||p.evidence?.scope!=='protected-bootstrap'||
    p.evidence.headSha!==p.head||p.evidence.prNumber!==39||
    p.evidence.authorAgent!=='agy'||
    p.evidence.reviewerAgent!=='codex'||
    p.evidence.verdict!=='passed'||p.evidence.exitCode!==0||
    p.evidence.reviewReadonly!==true||
    p.evidence.reviewIsolated!==true||
    p.evidence.evidenceId!==deriveSignedCodexEvidenceId({
     reviewDigest:codex.reviewDigest,packDigest:p.packDigest
    }))deny();
 for(const name of GATES){
  const row=p.evidence.gates?.[name];
  if(row?.headSha!==p.head||row.verdict!=='passed'||
     !/^verified-[a-z0-9-]{6,100}$/.test(row.evidenceId||''))deny();
 }
 const branch=p.protectionEvidence;
 if(branch?.repository!=='al-hub/mcp-dev-hub'||
    branch.branch!=='main'||branch.headSha!==p.head||
    branch.enforceAdmins!==true||
    branch.requireConversationResolution!==true||
    branch.requiredApprovals!==0||branch.reviewRuleAbsent!==true||
    !Array.isArray(branch.requiredChecks)||
    !branch.requiredChecks.includes('bootstrap')||
    !/^verified-[a-z0-9-]{6,100}$/.test(branch.evidenceId||''))deny();
 const terminal=JSON.parse(codex.reviewJson);
 if(p.issuedAtMs<terminal.issuedAtMs||
    p.expiresAtMs>terminal.expiresAtMs||
    p.expiresAtMs<=nowMs)deny();
}

/** No out-of-band evidence generator here. Missing reviewer handoff or a
 * failed physical/live check is terminal and never creates a signature.
 */
export async function issueFixedIndependentAppAcceptanceApproval(){
 assertRoleRuntimeInstalled({
  role:'approval',moduleUrl:import.meta.url,argv:process.argv
 });
 const context=readFixedIssuerContext();
 const handoff=readFixedAppAcceptanceReviewerHandoff();
 const receipt=readFixedIndependentCodexReceipt();
 const nowMs=Date.now();
 const reviewer=verifyAppAcceptanceReviewer({
  ...handoff,head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:context.packDigest,nowMs
 });
 const codex=verifyIndependentSignedReview({
  reviewJson:receipt.reviewJson,
  signatureBase64:receipt.reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem:handoff.pinnedReviewerPublicKeyPem,
  head:context.head,base:context.base,
  prNumber:context.prNumber,nowMs
 });
 validateLiveAcceptanceGates(reviewer.packet,context,
  {...codex,reviewJson:receipt.reviewJson},nowMs);
 const token=readFixedIssuerToken('approval');
 const originals=physicalOriginal();
 const [gh,baseline]=await Promise.all([
  fetchAndVerifyGitHubBootstrapEvidence({
   prNumber:39,head:context.head,base:context.base,
   ciRunId:context.ciRunId,githubToken:token
  }),
  fetchAndVerifyGitHubControllerPair({
   head:context.baselineCommit,manifestFiles:originals,githubToken:token
  })
 ]);
 if(gh.head!==context.head||gh.base!==context.base||
    !gh.ciPassed||!gh.strictProtection||
    NAMES.some(name=>!baseline[name]||
     hash(baseline[name])!==originals.find(f=>f.name===name)?.sha256))
   deny();
 // Re-validate the independent review signature and receipt after network
 // latency; expiry or moved CI must not be signed into an acceptance.
 const finalTime=Date.now();
 verifyAppAcceptanceReviewer({...handoff,
  head:context.head,base:context.base,
  ciRunId:context.ciRunId,packDigest:context.packDigest,
  nowMs:finalTime
 });
 verifyIndependentSignedReview({
  reviewJson:receipt.reviewJson,
  signatureBase64:receipt.reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:receipt.codexReviewerPublicKeyPem,
  pinnedApprovalPublicKeyPem:handoff.pinnedReviewerPublicKeyPem,
  head:context.head,base:context.base,prNumber:39,nowMs:finalTime
 });
 validateLiveAcceptanceGates(reviewer.packet,context,
  {...codex,reviewJson:receipt.reviewJson},finalTime);
 // The network request must not leave an old file snapshot eligible for
 // a later approval signature. Fail on replacement even with same SHA.
 verifyUnchangedPhysicalOriginal(originals,physicalOriginal());
 const signatureBase64=signFixedRolePayload({
  role:'approval',domain:APP_ACCEPTANCE_DOMAIN,json:handoff.raw
 });
 return Object.freeze({signatureBase64,packetSha256:hash(handoff.raw),
  safeToInstall:false,safeToReplay:false});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const r=await issueFixedIndependentAppAcceptanceApproval();
  process.stdout.write(JSON.stringify(r)+'\n');
 }catch{
  process.stderr.write('protected_app_acceptance_issuer_denied\n');
  process.exitCode=78;
 }
}
