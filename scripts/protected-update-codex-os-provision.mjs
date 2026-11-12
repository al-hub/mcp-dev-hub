// #35: fixed one-shot C-mode Codex signing OS principal provisioner CANDIDATE.
// Root-only, exact staged immutable entrypoint; NEVER run from a checkout.
// Requires separately locally authenticated owner trust and authorization.
// Creates no approval or review receipt. Partial failure is UNKNOWN, not retryable.
import {createHash,createPublicKey} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {constants,closeSync,fchmodSync,fchownSync,fstatSync,fsyncSync,
  lstatSync,mkdirSync,openSync,readFileSync,readSync,writeSync,chmodSync,
  chownSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {assertFixedCodexSignerPrerequisites}
  from '../src/ops/protected-update-issuer-boundary.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-codex-os-provision.mjs';
const CODE=ROOT+'/protected-codex';
const TRUST='/etc/mcp-dev-hub/protected-update';
const STATE='/var/lib/mcp-dev-hub-codex-review';
const PRIVATE=STATE+'/runner';
const ROLE='mcp35_codex';
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;
const FILES=Object.freeze([
  'scripts/protected-update-codex-receipt.mjs',
  'src/ops/protected-update-codex-terminal.mjs',
  'src/ops/protected-update-github-evidence.mjs'
]);
const EXEC=Object.freeze([
  ['/usr/local/lib/mcp-dev-hub/codex','codex-cli-sha256'],
  ['/usr/local/lib/mcp-dev-hub/codex-code-mode-host','codex-companion-sha256'],
  ['/usr/bin/bwrap','bwrap-sha256']
]);
const deny=()=>{throw Error('protected_codex_os_provision_denied_or_unknown');};
const KEYGEN=String.raw`
const fs=require('node:fs');
const {generateKeyPairSync}=require('node:crypto');
const dest='/var/lib/mcp-dev-hub-codex-review/runner/private.ed25519.pem';
if(process.argv.length!==1)process.exit(50);
const pair=generateKeyPairSync('ed25519');
const key=Buffer.from(pair.privateKey.export({format:'pem',type:'pkcs8'}));
const fd=fs.openSync(dest,fs.constants.O_WRONLY|fs.constants.O_CREAT|
  fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o400);
try{let off=0;while(off<key.length){
 const n=fs.writeSync(fd,key,off,key.length-off,off);
 if(n<=0)process.exit(51);off+=n;
}fs.fchmodSync(fd,0o400);fs.fsyncSync(fd);}
finally{fs.closeSync(fd);}
process.stdout.write(pair.publicKey.export({format:'pem',type:'spki'}));
`;
export const PROTECTED_CODEX_KEYGEN_PROGRAM=KEYGEN;
function dir(path,mode=null,owner=0){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
    (s.mode&0o022)!==0||
    (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function absent(path){
 try{lstatSync(path);deny();}catch(e){if(e.code!=='ENOENT')throw e;}
}
function syncDir(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
   constants.O_NOFOLLOW);
 try{fsyncSync(fd);}finally{closeSync(fd);}
}
function read(path,owner,mode,max){
 const fd=openSync(path,READ);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==owner||s.nlink!==1||
     (s.mode&0o777)!==mode||s.size<1||s.size>max)deny();
  const b=readFileSync(fd);
  if(b.length!==s.size)deny();
  return b;
 }finally{closeSync(fd);}
}
function trusted(name,max=16384){
 return read(TRUST+'/'+name,0,0o400,max);
}
function number(name){
 const v=trusted(name,16).toString('utf8').trim();
 if(!/^[1-9][0-9]{0,8}$/.test(v))deny();
 return Number(v);
}
function exclusive(path,data,mode,uid=0,gid=0){
 const b=Buffer.isBuffer(data)?data:Buffer.from(data,'utf8');
 if(b.length<1||b.length>131072)deny();
 const fd=openSync(path,WRITE,0o600);
 try{
  fchownSync(fd,uid,gid);
  let off=0;
  while(off<b.length){
   const n=writeSync(fd,b,off,b.length-off,off);
   if(n<=0)deny();off+=n;
  }
  fchmodSync(fd,mode);fsyncSync(fd);
  const s=fstatSync(fd);
  if(!s.isFile()||s.nlink!==1||s.uid!==uid||
     s.gid!==gid||(s.mode&0o777)!==mode||s.size!==b.length)deny();
 }finally{closeSync(fd);}
}
function verifyExec(path,hash){
 if(!HASH.test(hash))deny();
 const fd=openSync(path,READ);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
     (s.mode&0o777)!==0o755||s.size<1||
     s.size>384*1024*1024)deny();
  const digest=createHash('sha256'),buf=Buffer.alloc(65536);
  let off=0;
  while(off<s.size){
   const n=readSync(fd,buf,0,Math.min(buf.length,s.size-off),off);
   if(n<=0)deny();digest.update(buf.subarray(0,n));off+=n;
  }
  const after=fstatSync(fd);
  if(after.ino!==s.ino||after.dev!==s.dev||
     after.size!==s.size||after.mtimeMs!==s.mtimeMs||
     digest.digest('hex')!==hash)deny();
 }finally{closeSync(fd);}
}
function missingIdentity(){
 for(const kind of ['passwd','group']){
  const p=spawnSync('/usr/bin/getent',[kind,ROLE],{
   shell:false,encoding:'utf8',timeout:5000,maxBuffer:1024,
   env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']
  });
  if(p.error||p.signal||p.status!==2)deny();
 }
}
function identity(){
 const get=kind=>{
  const p=spawnSync('/usr/bin/getent',[kind,ROLE],{
   shell:false,encoding:'utf8',timeout:5000,maxBuffer:1024,
   env:{PATH:'/usr/bin:/bin'},stdio:['ignore','pipe','pipe']
  });
  if(p.error||p.signal||p.status!==0)deny();
  return p.stdout.trim().split(':');
 };
 const u=get('passwd'),g=get('group');
 if(u.length!==7||g.length!==4||u[0]!==ROLE||g[0]!==ROLE||
    !/^[1-9][0-9]{0,8}$/.test(u[2])||
    !/^[1-9][0-9]{0,8}$/.test(u[3])||
    !/^[1-9][0-9]{0,8}$/.test(g[2])||u[3]!==g[2])deny();
 return {uid:Number(u[2]),gid:Number(u[3])};
}
/** Pure shape check, NOT a privilege grant or independently verified identity. */
export function verifyCodexOSProvisionPlan({head,approvedHead,
  packVerified,workerUid,workerGid}={}){
 if(!SHA.test(head||'')||head!==approvedHead||packVerified!==true||
    !Number.isSafeInteger(workerUid)||workerUid<=0||
    !Number.isSafeInteger(workerGid)||workerGid<=0)deny();
 return Object.freeze({phase:'codex_os_provision_preflight_only',
  account:ROLE,ownerApproved:false,authorizationIssued:false,
  retrySafe:false});
}
export function provisionCodexSignerOSOnce(){
 // IMPORTANT: existing root-owned staged code, not a mutable checkout.
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)
   deny();
 process.umask(0o077);
 for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
   PACK,PACK+'/code',PACK+'/code/scripts',
   '/var','/var/lib','/etc','/etc/mcp-dev-hub',TRUST])dir(p);
 dir(PACK,0o700);dir(PACK+'/code',0o700);
 dir(PACK+'/code/scripts',0o700);dir(TRUST,0o700);
 const mode=trusted('signer-mode',64).toString('utf8').trim();
 if(mode!=='wsl-local-v1')deny();
 const digest=trusted('approved-pack-digest',128).toString('utf8').trim();
 if(!HASH.test(digest))deny();
 const pack=verifyProtectedBootstrapPack({
  outputPath:PACK,expectedManifestSha256:digest
 });
 if(pack.status!=='source_only_unprivileged_no_go'||pack.head!==
    trusted('approved-head',128).toString('utf8').trim())deny();
 const workerUid=number('worker-uid'),workerGid=number('worker-gid');
 verifyCodexOSProvisionPlan({head:pack.head,
  approvedHead:pack.head,packVerified:true,workerUid,workerGid});
 for(const [path,name] of EXEC)
  verifyExec(path,trusted(name,128).toString('utf8').trim());
 const auth=trusted('codex-auth.json',16384);
 try{JSON.parse(auth.toString('utf8'));}catch{deny();}
 missingIdentity();
 for(const p of [CODE,STATE,TRUST+'/codex-reviewer-public.pem',
   TRUST+'/codex-uid',TRUST+'/codex-gid'])absent(p);
 // Everything above precedes the FIRST OS mutation; never auto-retry.
 const created=spawnSync('/usr/sbin/useradd',[
  '--system','--user-group','--no-create-home',
  '--shell','/usr/sbin/nologin',ROLE
 ],{shell:false,timeout:15000,maxBuffer:1024,
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin'},
    stdio:['ignore','pipe','pipe']});
 if(created.error||created.signal||created.status!==0)deny();
 const {uid,gid}=identity();
 if(uid===workerUid||gid===workerGid)deny();
 mkdirSync(CODE,{mode:0o755});
 mkdirSync(CODE+'/code',{mode:0o755});
 mkdirSync(CODE+'/code/scripts',{mode:0o755});
 mkdirSync(CODE+'/code/src',{mode:0o755});
 mkdirSync(CODE+'/code/src/ops',{mode:0o755});
 for(const path of FILES){
  const row=pack.files.find(x=>x.path===path);
  if(!row)deny();
  const bytes=read(PACK+'/code/'+path,0,0o444,131072);
  if(bytes.length!==row.bytes||
     createHash('sha256').update(bytes).digest('hex')!==row.sha256)deny();
  exclusive(CODE+'/code/'+path,bytes,0o444);
 }
 mkdirSync(STATE,{mode:0o755});
 mkdirSync(PRIVATE,{mode:0o700});
 chownSync(PRIVATE,uid,gid);chmodSync(PRIVATE,0o700);
 exclusive(PRIVATE+'/codex-auth.json',auth,0o400,uid,gid);
 const child=spawnSync('/usr/bin/node',['-e',KEYGEN],{
  uid,gid,shell:false,encoding:'utf8',timeout:15000,maxBuffer:2048,
  env:{PATH:'/usr/bin:/bin',LANG:'C'},
  stdio:['ignore','pipe','pipe']
 });
 if(child.error||child.signal||child.status!==0||
    typeof child.stdout!=='string'||child.stdout.length>2048)deny();
 let pub;
 try{pub=createPublicKey(child.stdout);}catch{deny();}
 if(pub.asymmetricKeyType!=='ed25519'||pub.export({
   format:'pem',type:'spki'
 })!==child.stdout)deny();
 exclusive(TRUST+'/codex-reviewer-public.pem',child.stdout,0o400);
 exclusive(TRUST+'/codex-uid',String(uid),0o400);
 exclusive(TRUST+'/codex-gid',String(gid),0o400);
 syncDir(PRIVATE);syncDir(STATE);syncDir(TRUST);syncDir(CODE);
 assertFixedCodexSignerPrerequisites();
 return Object.freeze({phase:'codex_signer_os_role_staged_no_review',
  roleSeparated:true,secretExported:false,receiptIssued:false,
  installerAuthorized:false,safeToRetry:false});
}
if(process.argv[1]&&fileURLToPath(import.meta.url)===process.argv[1]){
 try{
  const r=provisionCodexSignerOSOnce();
  process.stdout.write(JSON.stringify(r)+'\n');
 }catch{
  process.stderr.write('protected_codex_os_provision_denied_or_unknown\n');
  process.exitCode=1;
 }
}
