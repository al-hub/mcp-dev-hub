// #35 immutable, root-owned, no-argument existing-App READ-ONLY token refresh.
// Source candidate: NOT installed. Root bootstrap must pin and protect PEM,
// code digest and timer. Nothing here signs, approves, updates controller
// files, authorizes sudo, or changes the existing App's granted permissions.
import {constants,closeSync,fchmodSync,fchownSync,fstatSync,fsyncSync,
 lstatSync,mkdirSync,openSync,readFileSync,renameSync,rmdirSync,writeSync}
 from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
 from './protected-update-bootstrap-pack.mjs';
import {assertFixedOperationalIssuerIsolation}
 from '../src/ops/protected-update-issuer-boundary.mjs';
import {createExistingAppJWT,verifyExistingAppAndInstallation,
 requestScopedReadOnlyToken}
 from '../src/ops/protected-update-app-readonly-token.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-app-token-refresh.mjs';
const TRUST='/etc/mcp-dev-hub/protected-update';
const BASE='/var/lib/mcp-dev-hub-signers';
const LOCK=TRUST+'/.readonly-token-refresh.lock';
const STAGE=BASE+'/.readonly-token-refresh.pending';
const ROLES=Object.freeze([
 Object.freeze({name:'reviewer',user:'mcp35_reviewer'}),
 Object.freeze({name:'approval',user:'mcp35_approver'})
]);
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const CREATE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
 constants.O_NOFOLLOW;
const deny=()=>{throw Error('protected_app_token_refresh_denied_or_unknown');};
const isInt=x=>Number.isSafeInteger(x)&&x>0;
function dir(path,uid=0,mode=null){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==uid||
   (s.mode&0o022)!==0||
   (mode!==null&&(s.mode&0o777)!==mode))deny();
 return s;
}
function missing(path){
 try{lstatSync(path);deny();}
 catch(e){if(e.code!=='ENOENT')throw e;}
}
function owned(path,uid,mode,maxBytes){
 const fd=openSync(path,READ);
 try{
  const st=fstatSync(fd);
  if(!st.isFile()||st.uid!==uid||st.nlink!==1||
    (st.mode&0o777)!==mode||st.size<1||st.size>maxBytes)deny();
  const b=readFileSync(fd);
  if(b.length!==st.size)deny();
  return b.toString('utf8');
 }finally{closeSync(fd);}
}
function rootTrust(name,max=4096){
 return owned(TRUST+'/'+name,0,0o400,max);
}
function sync(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
   constants.O_NOFOLLOW);
 try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
 finally{closeSync(fd);}
}
function account(name){
 const p=spawnSync('/usr/bin/getent',['passwd',name],{
  encoding:'utf8',shell:false,timeout:5000,maxBuffer:1024,
  env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']
 });
 if(p.error||p.signal||![0,2].includes(p.status))deny();
 if(p.status===2)return null;
 const row=p.stdout.trim().split(':');
 const uid=Number(row[2]),gid=Number(row[3]);
 if(row.length!==7||!isInt(uid)||!isInt(gid)||
    row[0]!==name||row[6]!=='/usr/sbin/nologin')deny();
 return {uid,gid};
}
export function decideRefreshPhase({codex,reviewer,approval}={}){
 if(!codex||!isInt(codex.uid)||!isInt(codex.gid))deny();
 if(!reviewer&&!approval)return 'bootstrap';
 if(!reviewer||!approval||
   !isInt(reviewer.uid)||!isInt(reviewer.gid)||
   !isInt(approval.uid)||!isInt(approval.gid)||
   new Set([codex.uid,reviewer.uid,approval.uid]).size!==3||
   new Set([codex.gid,reviewer.gid,approval.gid]).size!==3)deny();
 return 'routine';
}
function target(path,uid,gid,initial){
 if(initial){missing(path);return;}
 const fd=openSync(path,READ);
 try{
  const st=fstatSync(fd);
  if(!st.isFile()||st.uid!==uid||st.gid!==gid||
     st.nlink!==1||(st.mode&0o777)!==0o400||
     st.size<12||st.size>4096)deny();
 }finally{closeSync(fd);}
}
function staged(path,token,uid,gid){
 missing(path);
 const data=Buffer.from(token,'utf8');
 if(data.length<20||data.length>4096)deny();
 const fd=openSync(path,CREATE,0o400);
 try{
  let n=0;
  while(n<data.length){
   const wrote=writeSync(fd,data,n,data.length-n,n);
   if(wrote<=0)deny();
   n+=wrote;
  }
  fchownSync(fd,uid,gid);
  fchmodSync(fd,0o400);
  fsyncSync(fd);
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==uid||s.gid!==gid||s.nlink!==1||
     (s.mode&0o777)!==0o400||s.size!==data.length)deny();
 }finally{closeSync(fd);}
}
async function json(reqUrl,bearer,method='GET',body=null){
 const r=await fetch('https://api.github.com'+reqUrl,{
  method,redirect:'error',signal:AbortSignal.timeout(20000),
  headers:{Authorization:'Bearer '+bearer,
   Accept:'application/vnd.github+json',
   'User-Agent':'mcp-dev-hub-protected-readonly-refresh',
   ...(body?{'Content-Type':'application/json'}:{})},
  body:body?JSON.stringify(body):undefined
 });
 const reader=r.body?.getReader();
 if(!reader)deny();
 let total=0;const chunks=[];
 try{
  while(true){
   const {done,value}=await reader.read();
   if(done)break;
   total+=value.byteLength;
   if(total>262144)deny();
   chunks.push(value);
  }
 }finally{reader.releaseLock();}
 let data;
 try{data=JSON.parse(Buffer.concat(chunks).toString('utf8'));}
 catch{deny();}
 return {status:r.status,body:data};
}
async function scopeProbe(token){
 const root='/repos/al-hub/mcp-dev-hub';
 for(const path of [
  root+'/branches/main/protection',
  root+'/actions/runs?per_page=1',
  root+'/commits/main/check-runs?per_page=1',
  root+'/commits/main/statuses?per_page=1',
  root+'/rulesets?includes_parents=true&per_page=1',
  root+'/contents/package.json',root+'/pulls?per_page=1'
 ]){
  if((await json(path,token)).status!==200)deny();
 }
 const graph=await json('/graphql',token,'POST',{
  query:'query{repository(owner:"al-hub",name:"mcp-dev-hub"){name}}'
 });
 if(graph.status!==200||graph.body?.errors||
   graph.body?.data?.repository?.name!=='mcp-dev-hub')deny();
}
function assurePaths(phase,reviewer,approval){
 for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
  PACK,PACK+'/code',PACK+'/code/scripts',
  '/etc','/etc/mcp-dev-hub',TRUST,'/var','/var/lib'])dir(p);
 dir(PACK,0,0o700);dir(TRUST,0,0o700);
 if(phase==='routine'){
  dir(BASE,0,0o755);
  for(const [r,identity] of [[ROLES[0],reviewer],[ROLES[1],approval]]){
   dir(BASE+'/issuer-'+r.name,identity.uid,0o700);
   target(BASE+'/issuer-'+r.name+'/github-readonly-token',
     identity.uid,identity.gid,false);
  }
  missing(STAGE);
  assertFixedOperationalIssuerIsolation();
 }else missing(BASE);
 const rootInputs=['github-token','reviewer-github-readonly-token',
  'approval-github-readonly-token'];
 let firstMint=false;
 if(phase==='bootstrap'){
  let present=0;
  for(const name of rootInputs){
   try{lstatSync(TRUST+'/'+name);present++;}
   catch(e){if(e?.code!=='ENOENT')throw e;}
  }
  if(present!==0&&present!==3)deny();
  firstMint=present===0;
 }
 for(const name of rootInputs)target(TRUST+'/'+name,0,0,firstMint);
 for(const name of rootInputs)missing(TRUST+'/.'+name+'.pending');
 return Object.freeze({firstMint});
}
function readRefreshState(){
 const codex=account('mcp35_codex');
 const reviewer=account('mcp35_reviewer');
 const approval=account('mcp35_approver');
 const phase=decideRefreshPhase({codex,reviewer,approval});
 const {firstMint}=assurePaths(phase,reviewer,approval);
 return {codex,reviewer,approval,phase,firstMint};
}
export function assertUnchangedRefreshState(before,current){
 const sameIdentity=(a,b)=>a===null||b===null?a===b:
  a.uid===b.uid&&a.gid===b.gid;
 if(before.phase!==current.phase||before.firstMint!==current.firstMint||
   !['codex','reviewer','approval'].every(role=>
    sameIdentity(before[role],current[role])))deny();
}
export async function refreshPinnedAppReadOnlyTokens(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY||
    process.execArgv.length!==0||
    process.env.NODE_OPTIONS)deny();
 process.umask(0o077);
 const before=readRefreshState();
 missing(LOCK);
 const digest=rootTrust('approved-pack-digest',128).trim();
 const head=rootTrust('approved-head',128).trim();
 const pack=verifyProtectedBootstrapPack({
  outputPath:PACK,expectedManifestSha256:digest
 });
 if(pack.status!=='source_only_unprivileged_no_go'||
   pack.head!==head||rootTrust('signer-mode',64).trim()!=='wsl-local-v1')
  deny();
 const key=rootTrust('existing-reviewer-app-private.pem',16384);
 const jwt=createExistingAppJWT(key);
 const [app,installation]=await Promise.all([
  json('/app',jwt),
  json('/repos/al-hub/mcp-dev-hub/installation',jwt)
 ]);
 if(app.status!==200||installation.status!==200)deny();
 const pinned=verifyExistingAppAndInstallation(app.body,installation.body);
 const tokens=[];
 for(let i=0;i<3;i++){
  const entry=await requestScopedReadOnlyToken({
   appJwt:jwt,installationId:pinned.installationId,
   post:async req=>json(req.path,req.authorization,req.method,req.body)
  });
  await scopeProbe(entry.token);
  tokens.push(entry);
 }
 if(new Set(tokens.map(x=>x.token)).size!==3)deny();
 if(tokens.some(x=>x.expiresAtMs-Date.now()<25*60_000))deny();
 mkdirSync(LOCK,{mode:0o700});dir(LOCK,0,0o700);sync(TRUST);
 let current;
 try{
  current=readRefreshState();
  assertUnchangedRefreshState(before,current);
 }catch(e){
  // No token was staged or replaced. Release our own preflight-only fence.
  rmdirSync(LOCK);sync(TRUST);
  throw e;
 }
 const {reviewer,approval,phase,firstMint}=current;
 // From the first token write, failures are UNKNOWN and retain the fence.
 const names=['github-token','reviewer-github-readonly-token',
  'approval-github-readonly-token'];
 for(let i=0;i<3;i++)staged(TRUST+'/.'+names[i]+'.pending',
   tokens[i].token,0,0);
 if(phase==='routine'){
  mkdirSync(STAGE,{mode:0o700});dir(STAGE,0,0o700);
  staged(STAGE+'/reviewer-token.pending',tokens[1].token,
    reviewer.uid,reviewer.gid);
  staged(STAGE+'/approval-token.pending',tokens[2].token,
    approval.uid,approval.gid);
  sync(STAGE);
 }
 sync(TRUST);
 for(const name of names)
  target(TRUST+'/'+name,0,0,firstMint);
 for(const name of names)
  renameSync(TRUST+'/.'+name+'.pending',TRUST+'/'+name);
 if(phase==='routine'){
  for(const [name,role] of [['reviewer',ROLES[0]],['approval',ROLES[1]]])
   renameSync(STAGE+'/'+name+'-token.pending',
    BASE+'/issuer-'+role.name+'/github-readonly-token');
  sync(BASE+'/issuer-reviewer');sync(BASE+'/issuer-approval');
  rmdirSync(STAGE);sync(BASE);
 }
 sync(TRUST);
 for(const name of names)target(TRUST+'/'+name,0,0,false);
 if(phase==='routine')
  for(const [r,i] of [[ROLES[0],reviewer],[ROLES[1],approval]])
   target(BASE+'/issuer-'+r.name+'/github-readonly-token',
    i.uid,i.gid,false);
 rmdirSync(LOCK);sync(TRUST);
 return Object.freeze({state:'fixed_readonly_tokens_refreshed',
  phase,rolesUpdated:phase==='routine'?2:0,authorizationIssued:false,
  appWriteScopeDelegated:false,installAuthorized:false});
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const r=await refreshPinnedAppReadOnlyTokens();
  process.stdout.write(JSON.stringify(r)+'\n');
 }catch{
  process.stderr.write('protected_app_token_refresh_denied_or_unknown\n');
  process.exitCode=1;
 }
}
