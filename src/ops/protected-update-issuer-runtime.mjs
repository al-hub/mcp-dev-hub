// #35 UNINSTALLED issuer runtime library. Two *distinct* OS uid/gid
// principals own keys and independently fetch GitHub evidence. This module
// never elevates or changes root files. Runtime source must be copied from
// a separately approved exact-HEAD bundle into a fixed root-owned (0555
// directories, 0444 files) readable issuer-code path by ONE admin bootstrap.
// It is never safe to execute from a Worker checkout.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';
import {createPrivateKey,sign} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {parsePinnedBootstrapIssuerContext}
  from './protected-update-bootstrap-issuer.mjs';
import {parsePinnedRoutineIssuerContext,ROUTINE_REVIEW_DOMAIN,
  ROUTINE_APPROVAL_DOMAIN}
  from './protected-update-routine-issuer.mjs';
import {APP_ACCEPTANCE_DOMAIN}
  from './protected-update-app-acceptance.mjs';
import {fetchAndVerifyGitHubBootstrapEvidence,
  fetchAndVerifyOfficialReviewerApproval}
  from './protected-update-github-evidence.mjs';

const BASE='/var/lib/mcp-dev-hub-signers';
const ROUTINE_ID=/^[a-f0-9]{32}$/;
export function fixedRoutineOperationId(value){
  if(typeof value!=='string'||!ROUTINE_ID.test(value))
    throw Error('protected_signer_runtime_denied');
  return value;
}
function routineSlot(){
  const id=fixedRoutineOperationId(process.env.MCP_PROTECTED_OPERATION_ID);
  checkedDir(BASE,0);
  checkedDir(BASE+'/routine-operations',0,0o755);
  const slot=BASE+'/routine-operations/'+id;
  checkedDir(slot,0,0o755);
  return slot;
}
const CODE='/usr/local/lib/mcp-dev-hub/protected-issuer/code';
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const deny=()=>{throw Error('protected_signer_runtime_denied');};
const ROLE=Object.freeze({
  reviewer:Object.freeze([
    'protected-update-review-issuer.mjs',
    'protected-update-routine-review-issuer.mjs'
  ]),
  approval:Object.freeze([
    'protected-update-approval-issuer.mjs',
    'protected-update-routine-approval-issuer.mjs',
    'protected-update-app-acceptance-approval-issuer.mjs'
  ])
});
function checkedDir(path,owner,mode=null){
  const s=lstatSync(path);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
     (s.mode&0o022)!==0||
     (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function readExact(path,{owner,mode,maxBytes,group=null}){
  const fd=openSync(path,READ);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==owner||s.nlink!==1||
       (s.mode&0o777)!==mode||
       (group!==null&&s.gid!==group)||
       s.size<1||s.size>maxBytes)deny();
    const b=readFileSync(fd);
    if(b.length!==s.size)deny();
    return b.toString('utf8');
  }finally{closeSync(fd);}
}
export function assertRoleRuntimeInstalled({role,moduleUrl,argv}={}){
  if(!Object.hasOwn(ROLE,role)||typeof moduleUrl!=='string'||
     typeof process.getuid!=='function'||
     process.getuid()===0||process.geteuid?.()!==process.getuid()||
     !Array.isArray(argv)||argv.length!==2||
     !ROLE[role].some(name=>fileURLToPath(moduleUrl)===
       CODE+'/scripts/'+name))deny();
  const uid=process.getuid(),gid=process.getgid();
  if(!Number.isSafeInteger(uid)||uid<=0||
     !Number.isSafeInteger(gid)||gid<=0)deny();
  if(process.getgroups?.().some(g=>g!==gid))deny();
  for(const p of [
    '/','/usr','/usr/local','/usr/local/lib',
    '/usr/local/lib/mcp-dev-hub',
    '/usr/local/lib/mcp-dev-hub/protected-issuer',
    CODE,CODE+'/scripts',CODE+'/src',CODE+'/src/ops',
    '/var','/var/lib',BASE
  ])checkedDir(p,0);
  checkedDir(BASE+'/issuer-'+role,uid,0o700);
  const routine=fileURLToPath(moduleUrl).includes(
    '/scripts/protected-update-routine-');
  if(routine)routineSlot();
  else if(Object.hasOwn(process.env,'MCP_PROTECTED_OPERATION_ID'))deny();
  return Object.freeze({role,uid,gid});

}
export function readFixedRoutineIssuerContext(){
  checkedDir(BASE,0);
  return parsePinnedRoutineIssuerContext(readExact(
    routineSlot()+'/approved-routine-context.json',
    {owner:0,mode:0o444,maxBytes:6500}
  ));
}
export function readFixedIssuerContext(){
  checkedDir(BASE,0);
  return parsePinnedBootstrapIssuerContext(readExact(
    BASE+'/approved-bootstrap-context.json',
    {owner:0,mode:0o444,maxBytes:2048}
  ));
}
function readPrivateIssuerMaterial(role){
  if(!Object.hasOwn(ROLE,role))deny();
  const uid=process.getuid(),gid=process.getgid();
  checkedDir(BASE+'/issuer-'+role,uid,0o700);
  const key=readExact(
    BASE+'/issuer-'+role+'/private.ed25519.pem',
    {owner:uid,group:gid,mode:0o400,maxBytes:8192}
  );
  const token=readExact(
    BASE+'/issuer-'+role+'/github-readonly-token',
    {owner:uid,group:gid,mode:0o400,maxBytes:4096}
  ).trim();
  if(!/^[a-zA-Z0-9_.-]{8,4096}$/.test(token))deny();
  let privateKey;
  try{privateKey=createPrivateKey(key);}catch{deny();}
  if(privateKey.asymmetricKeyType!=='ed25519')deny();
  return {privateKey,token};
}
export async function fetchFixedIssuerEvidence(context,token){
  // Genuine TLS/GitHub evidence: PR must be NON-DRAFT, exact HEAD/BASE,
  // strict required CI and branch protection. Bot approval must be the
  // latest same-HEAD review from the fixed trusted reviewer identity.
  const [githubEvidence,officialApproval]=await Promise.all([
    fetchAndVerifyGitHubBootstrapEvidence({
      prNumber:context.prNumber,head:context.head,base:context.base,
      ciRunId:context.ciRunId,githubToken:token
    }),
    fetchAndVerifyOfficialReviewerApproval({
      prNumber:context.prNumber,head:context.head,
      reviewerBotId:context.reviewerBotId,githubToken:token,
      nowMs:Date.now()
    })
  ]);
  if(officialApproval.reviewActor!==context.reviewerBotActor||
     !/^verified-[a-z0-9-]{6,100}$/.test(
       officialApproval.reviewEvidenceId||''))deny();
  return {githubEvidence,officialApproval};
}
export function signFixedRolePayload({role,domain,json}={}){
  if(!Object.hasOwn(ROLE,role)||
     typeof domain!=='string'||typeof json!=='string'||
     Buffer.byteLength(json,'utf8')>2048)deny();
  const allowed=role==='reviewer'
    ?['mcp-dev-hub/bootstrap-independent-review/v1\n',
      ROUTINE_REVIEW_DOMAIN]
    :['mcp-dev-hub/bootstrap-approval/v1\n',
      ROUTINE_APPROVAL_DOMAIN];
  if(role==='approval'&&domain===APP_ACCEPTANCE_DOMAIN){
   // Only the fixed, audited App acceptance role may use this new domain.
   // Existing bootstrap/routine signers cannot silently widen authority.
   if(process.argv.length!==2||process.argv[1]!==
       CODE+'/scripts/protected-update-app-acceptance-approval-issuer.mjs')deny();
  }else if(!allowed.includes(domain))deny();
  const {privateKey}=readPrivateIssuerMaterial(role);
  return sign(null,Buffer.from(domain+json),privateKey)
    .toString('base64');
}
export function readFixedRoutineReviewerHandoff(){
  checkedDir(BASE,0);
  const raw=readExact(routineSlot()+'/routine-review-handoff.json',{
    owner:0,mode:0o444,maxBytes:5000
  });
  let value;
  try{value=JSON.parse(raw);}catch{deny();}
  if(!value||Array.isArray(value)||
     Object.keys(value).sort().join(',')!==
       'reviewJson,reviewSignatureBase64'||
     JSON.stringify(value)!==raw||
     typeof value.reviewJson!=='string'||
     typeof value.reviewSignatureBase64!=='string')deny();
  const reviewerPublicKeyPem=readExact(
    BASE+'/reviewer-public.pem',
    {owner:0,mode:0o444,maxBytes:4096}
  );
  return {reviewerPublicKeyPem,...value};
}
/** Root-staged, one-use acceptance data and independent reviewer handoff.
 * These public data files never provide the approval role a signer key.
 * A fixed root collector must independently verify and stage them.
 */
export function readFixedAppAcceptanceReviewerHandoff(){
 checkedDir(BASE,0);
 const raw=readExact(BASE+'/app-acceptance.json',{
  owner:0,mode:0o444,maxBytes:12000
 });
 const reviewSignatureBase64=readExact(
  BASE+'/app-acceptance.review.sig',{
   owner:0,mode:0o444,maxBytes:256
  }).trim();
 const pinnedReviewerPublicKeyPem=readExact(
  BASE+'/reviewer-public.pem',{
   owner:0,mode:0o444,maxBytes:4096
  });
 return Object.freeze({raw,reviewSignatureBase64,
  pinnedReviewerPublicKeyPem});
}
export function readFixedReviewerHandoff(){
  checkedDir(BASE,0);
  const raw=readExact(BASE+'/review-handoff.json',{
    owner:0,mode:0o444,maxBytes:5000
  });
  let value;
  try{value=JSON.parse(raw);}catch{deny();}
  if(!value||Array.isArray(value)||
     Object.keys(value).sort().join(',')!==
       'reviewJson,reviewSignatureBase64'||
     JSON.stringify(value)!==raw||
     typeof value.reviewJson!=='string'||
     typeof value.reviewSignatureBase64!=='string')deny();
  const reviewerPublicKeyPem=readExact(
    BASE+'/reviewer-public.pem',
    {owner:0,mode:0o444,maxBytes:4096}
  );
  return {reviewerPublicKeyPem,
    reviewJson:value.reviewJson,
    reviewSignatureBase64:value.reviewSignatureBase64};
}
/** Fixed root-staged independent Codex receipt. No Worker/PR supplied
 * key path, unsigned boolean or review-body text can replace this receipt.
 */
export function readFixedIndependentCodexReceipt(){
  checkedDir(BASE,0);
  return Object.freeze({
    reviewJson:readExact(BASE+'/codex-review.json',
      {owner:0,mode:0o444,maxBytes:2048}),
    reviewSignatureBase64:readExact(BASE+'/codex-review.sig',
      {owner:0,mode:0o444,maxBytes:256}).trim(),
    codexReviewerPublicKeyPem:readExact(BASE+'/codex-reviewer-public.pem',
      {owner:0,mode:0o444,maxBytes:4096}),
    issuerReviewerPublicKeyPem:readExact(BASE+'/reviewer-public.pem',
      {owner:0,mode:0o444,maxBytes:4096})
  });
}
export function readFixedIssuerToken(role){
  if(!Object.hasOwn(ROLE,role))deny();
  // No access to the peer role's private key or token.
  return readPrivateIssuerMaterial(role).token;
}
/** Operation-specific immutable Codex receipt. Bootstrap and App remain
 * bound to their separate fixed receipt; never fall back to earlier updates.
 */
export function readFixedRoutineCodexReceipt(){
  const dir=routineSlot();
  return Object.freeze({
    reviewJson:readExact(dir+'/codex-review.json',
      {owner:0,mode:0o444,maxBytes:2048}),
    reviewSignatureBase64:readExact(dir+'/codex-review.sig',
      {owner:0,mode:0o444,maxBytes:256}).trim(),
    codexReviewerPublicKeyPem:readExact(dir+'/codex-reviewer-public.pem',
      {owner:0,mode:0o444,maxBytes:4096}),
    issuerReviewerPublicKeyPem:readExact(dir+'/reviewer-public.pem',
      {owner:0,mode:0o444,maxBytes:4096})
  });
}
