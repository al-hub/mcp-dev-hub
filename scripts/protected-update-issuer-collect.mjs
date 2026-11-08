// #35 UNINSTALLED fixed-root one-shot issuer orchestration candidate.
// One owner-authorized root session must first stage a pinned source package,
// root-only evidence, two physically isolated role keypairs, scope-reduced
// GitHub read tokens and the root-owned 6-file issuer runtime. This command
// NEVER installs sudoers, changes the running controller, or retries unknown
// signer/HTTPS outcomes. Its outputs are root-only reviewed attestations.
// Worker cannot invoke arbitrary commands, signers, keys or payloads.
import {createHash} from 'node:crypto';
import {constants,closeSync,fstatSync,fsyncSync,lstatSync,openSync,
  readFileSync,writeSync,fchmodSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
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

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-issuer-collect.mjs';
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
  if(bytes.length<1||bytes.length>5000)deny();
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
function runRole(name,role){
  const uid=ownerNumber(role+'-uid'),gid=ownerNumber(role+'-gid');
  const path=CODE+'/scripts/'+name;
  const r=spawnSync('/usr/bin/node',[path],{
    uid,gid,cwd:'/',shell:false,encoding:'utf8',timeout:60000,
    maxBuffer:5000,stdio:['ignore','pipe','pipe'],
    env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',HOME:'/'}
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
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await collectFixedBootstrapIssuerAttestations();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_issuer_collect_denied_or_unknown\n');
    process.exitCode=1;
  }
}
