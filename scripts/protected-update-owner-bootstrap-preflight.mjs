// #35: read-only local-owner installation preflight and exact-packet handoff.
// Never elevates, installs, provisions roles/keys, reads credentials or
// treats user/Worker-provided digests as owner-signed authorization.
import {lstatSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve,isAbsolute} from 'node:path';
import {inspectExistingProtectedBootstrapBaseline}
  from './protected-update-bootstrap-readiness.mjs';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';

const SHA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const fail=()=>{throw Error('protected_owner_bootstrap_preflight_denied');};
const ROOT_PATHS=Object.freeze([
  {label:'protectedCodexSource',path:'/usr/local/lib/mcp-dev-hub/protected-codex'},
  {label:'protectedCodexState',path:'/var/lib/mcp-dev-hub-codex-review'},
  {label:'protectedIssuerSource',path:'/usr/local/lib/mcp-dev-hub/protected-issuer'},
  {label:'protectedIssuerState',path:'/var/lib/mcp-dev-hub-signers'},
  {label:'ownerPinnedTrust',path:'/etc/mcp-dev-hub/protected-update'},
  {label:'protectedUpdateState',path:'/var/lib/mcp-dev-hub/protected-update'}
]);
const ACCOUNTS=Object.freeze([
  {label:'codexRole',name:'mcp35_codex'},
  {label:'reviewerRole',name:'mcp35_reviewer'},
  {label:'approverRole',name:'mcp35_approver'}
]);
function checkedAbsolute(value){
 if(typeof value!=='string'||!isAbsolute(value)||value.length>4096||
    resolve(value)!==value)fail();
 return value;
}
function pathState(path){
 try{
  const stat=lstatSync(path);
  if(stat.isSymbolicLink()||!stat.isDirectory())return 'UNSAFE';
  return stat.uid===0&&(stat.mode&0o022)===0?'PRESENT_PROTECTED':'UNSAFE';
 }catch(e){
  if(e?.code==='ENOENT')return 'ABSENT';
  if(e?.code==='EACCES'||e?.code==='EPERM')return 'UNKNOWN';
  fail();
 }
}
function accountState(name){
 const r=spawnSync('/usr/bin/getent',['passwd',name],{
  shell:false,encoding:'utf8',timeout:5000,maxBuffer:1024,
  env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']
 });
 if(r.error||r.signal)return 'UNKNOWN';
 if(r.status===2)return 'ABSENT';
 // Never reveal account IDs or user-specific login data.
 if(r.status===0&&r.stdout.split(':')[0]===name)return 'PRESENT_UNVERIFIED';
 return 'UNKNOWN';
}
/** Pure result-shape guard for tests; caller values have NO OS authority. */
export function evaluateOwnerBootstrapHandoff({
 head,expectedHead,manifestSha256,expectedManifestSha256,
 fileCount,baselineConfirmed
}={}){
 if(!SHA.test(head||'')||head!==expectedHead||
    !HASH.test(manifestSha256||'')||
    manifestSha256!==expectedManifestSha256||
    !Number.isSafeInteger(fileCount)||fileCount<1||fileCount>100||
    baselineConfirmed!==true)fail();
 return Object.freeze({
  phase:'nonprivileged_owner_preflight_only',
  head,manifestSha256,fileCount,originalBaselineConfirmed:true,
  sourcePacketChecksumMatched:true,
  ownerIdentityAuthenticated:false,
  signerProvenanceVerified:false,
  independentGitHubApprovalVerified:false,
  privilegedInstallerApproved:false,
  rootInstallAuthorized:false,
  operationalReviewReceiptIssued:false,
  safeToMerge:false,safeToCloseIssue:false
 });
}
/**
 * The CLI is safe to run as the ordinary WSL owner only. The expected HEAD
 * and checksum MUST be checked out-of-band by the owner; even a positive
 * result grants NO sudo or root admission. No filenames, private paths,
 * actual credential contents or OS identities leave this function.
 */
export function inspectLocalOwnerBootstrapHandoff({
 repositoryPath,baselineCommit,outputPath,head,expectedManifestSha256
}={}){
 if(process.getuid?.()===0||process.geteuid?.()===0||
    process.getuid?.()!==process.geteuid?.()||
    !SHA.test(baselineCommit||'')||!SHA.test(head||'')||
    !HASH.test(expectedManifestSha256||''))fail();
 checkedAbsolute(repositoryPath);checkedAbsolute(outputPath);
 const baseline=inspectExistingProtectedBootstrapBaseline({
  repositoryPath,baselineCommit
 });
 if(baseline.status!=='original_baseline_and_isolated_startup_confirmed'||
    baseline.installerAuthorized!==false||
    baseline.realProtectedUpdates!==0)fail();
 const pack=verifyProtectedBootstrapPack({
  outputPath,expectedManifestSha256
 });
 if(pack.status!=='source_only_unprivileged_no_go')fail();
 const result=evaluateOwnerBootstrapHandoff({
  head:pack.head,expectedHead:head,
  manifestSha256:pack.manifestSha256,expectedManifestSha256,
  fileCount:pack.fileCount,baselineConfirmed:true
 });
 const observed=Object.freeze({
  rootPaths:Object.freeze(ROOT_PATHS.map(r=>Object.freeze({
   label:r.label,state:pathState(r.path)
  }))),
  identities:Object.freeze(ACCOUNTS.map(r=>Object.freeze({
   label:r.label,state:accountState(r.name)
  })))
 });
 return Object.freeze({...result,observed});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  if(process.argv.length!==7)fail();
  const [, ,repositoryPath,baselineCommit,outputPath,
    head,expectedManifestSha256]=process.argv;
  const result=inspectLocalOwnerBootstrapHandoff({
   repositoryPath,baselineCommit,outputPath,head,expectedManifestSha256
  });
  process.stdout.write(JSON.stringify(result)+'\n');
 }catch{
  process.stderr.write('protected_owner_bootstrap_preflight_denied\n');
  process.exitCode=1;
 }
}
