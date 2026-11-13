// #35 C-mode local-owner first immutable root PACK STAGING CANDIDATE ONLY.
// This standalone file is installed by the *actual local owner* as fixed,
// independently SHA256-pinned root-owned 0444 code BEFORE privileged execution.
// Never run directly from a mutable checkout. Does not provision signing roles,
// install sudoers, edit existing protected originals, or grant root update GO.
// One-shot effects are UNKNOWN on failure; do not automatically replay.
import {createHash} from 'node:crypto';
import {constants,closeSync,fchmodSync,fstatSync,fsyncSync,
 lstatSync,mkdirSync,openSync,readFileSync,opendirSync,
 readSync,realpathSync,renameSync,writeSync} from 'node:fs';
import {resolve,isAbsolute,dirname,join,posix} from 'node:path';
import {fileURLToPath} from 'node:url';

const ROOT='/usr/local/lib/mcp-dev-hub';
const ENTRY=ROOT+'/protected-owner-stage.mjs';
const DEST=ROOT+'/protected-updater';
const PENDING=ROOT+'/.protected-updater.pending';
const TRUST='/etc/mcp-dev-hub/protected-update';
const REPO='al-hub/mcp-dev-hub';
const SOURCE=Object.freeze([
 'scripts/protected-update-bootstrap-entry.mjs',
 'scripts/reviewer-app-trusted-preflight.mjs',
 'scripts/reviewer-app-trusted-publish.mjs',
 'scripts/protected-update-codex-receipt.mjs',
 'scripts/protected-update-codex-os-provision.mjs',
 'scripts/protected-update-owner-bootstrap-preflight.mjs',
 'scripts/protected-update-owner-root-stage.mjs',
 'scripts/protected-update-bootstrap-readiness.mjs',
 'scripts/protected-update-os-activate.mjs',
 'scripts/protected-update-issuer-provision.mjs',
 'scripts/protected-update-issuer-stage.mjs',
 'scripts/protected-update-issuer-collect.mjs',
   'scripts/protected-update-app-token-refresh.mjs',
 'scripts/protected-update-review-issuer.mjs',
 'scripts/protected-update-local-review-issuer.mjs',
 'scripts/protected-update-approval-issuer.mjs',
 'scripts/protected-update-local-approval-issuer.mjs',
 'scripts/protected-update-routine-review-issuer.mjs',
 'scripts/protected-update-routine-approval-issuer.mjs',
 'scripts/protected-update-app-acceptance-review-issuer.mjs',
 'scripts/protected-update-app-acceptance-approval-issuer.mjs',
 'scripts/protected-update-bootstrap-restore.mjs',
 'scripts/protected-update-bootstrap-pack.mjs',
 'scripts/protected-update-controller-wrapper.mjs',
 'scripts/protected-update-root-apply.mjs',
 'scripts/protected-update-root-reconcile.mjs',
 'src/jobs/github-app-review-publisher.mjs',
 'src/jobs/github-app-publication-fence.mjs',
 'src/ops/protected-update-app-acceptance.mjs',
 'src/ops/protected-update-app-gate-provenance.mjs',
   'src/ops/protected-update-app-readonly-token.mjs',
 'src/ops/protected-update-approval.mjs',
 'src/ops/protected-update-bootstrap-migration.mjs',
 'src/ops/protected-update-github-evidence.mjs',
 'src/ops/protected-update-codex-terminal.mjs',
 'src/ops/protected-update-health-probe.mjs',
 'src/ops/protected-update-operation-guard.mjs',
 'src/ops/protected-update-journal-store.mjs',
 'src/ops/protected-update-journal.mjs',
 'src/ops/protected-update-install-attestation.mjs',
 'src/ops/protected-update-issuer-boundary.mjs',
 'src/ops/protected-update-bootstrap-issuer.mjs',
 'src/ops/protected-update-local-issuer-claims.mjs',
 'src/ops/protected-update-local-trust-contract.mjs',
 'src/ops/protected-update-issuer-runtime.mjs',
 'src/ops/protected-update-legacy-capture.mjs',
 'src/ops/protected-update-manifest.mjs',
 'src/ops/protected-update-reconcile.mjs',
 'src/ops/protected-update-release-pointer.mjs',
 'src/ops/protected-update-request.mjs',
 'src/ops/protected-update-routine-issuer.mjs',
 'src/ops/protected-update-routine-collection.mjs',
 'src/ops/protected-update-routine-intent.mjs',
 'src/ops/protected-update-routine-stage.mjs',
 'src/ops/protected-update-routine-reconcile.mjs',
 'src/ops/protected-update-routine-dispatch-fence.mjs',
 'src/ops/protected-update-root-evidence.mjs',
 'src/ops/protected-update-root-layout.mjs',
 'src/ops/protected-update-root-preflight.mjs',
 'src/ops/protected-update-sudo-policy.mjs',
 'src/ops/protected-update-transaction.mjs',
 'systemd/mcp-dev-hub-app-token-refresh.service',
   'systemd/mcp-dev-hub-app-token-refresh.timer',
   '.github/workflows/ci.yml',
 'package.json',
 'scripts/check-privacy.mjs',
 'scripts/privacy-rules.mjs'
]);
export const OWNER_STAGE_FILES=SOURCE;
const SHA=/^[0-9a-f]{40}$/;
const HASH=/^[0-9a-f]{64}$/;
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
 constants.O_NOFOLLOW;
const MAX_FILE=262144,MAX_PACKAGE=2*1024*1024;
const deny=()=>{throw Error('protected_owner_root_stage_denied_or_unknown');};
const digest=b=>createHash('sha256').update(b).digest('hex');
function isExact(o,keys){
 return o&&typeof o==='object'&&!Array.isArray(o)&&
  Object.keys(o).length===keys.length&&keys.every(k=>Object.hasOwn(o,k));
}
function dir(path,owner,mode){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
    (mode!==null&&(s.mode&0o777)!==mode)||
    (s.mode&0o022)!==0)deny();
}
function rootDir(path,mode=null){dir(path,0,mode);}
function absent(path){
 try{lstatSync(path);deny();}catch(e){if(e?.code!=='ENOENT')throw e;}
}
function syncDir(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
   constants.O_NOFOLLOW);
 try{fsyncSync(fd);}finally{closeSync(fd);}
}
function fileBytes(path,owner,mode,max){
 const fd=openSync(path,READ);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==owner||s.nlink!==1||
     (s.mode&0o777)!==mode||s.size<1||s.size>max)deny();
  const out=Buffer.alloc(s.size);
  let off=0;
  while(off<out.length){
   const n=readSync(fd,out,off,out.length-off,off);
   if(n<=0)deny();off+=n;
  }
  const after=fstatSync(fd),pathStat=lstatSync(path);
  if(after.dev!==s.dev||after.ino!==s.ino||
     after.size!==s.size||after.mtimeMs!==s.mtimeMs||
     pathStat.dev!==s.dev||pathStat.ino!==s.ino)deny();
  return out;
 }finally{closeSync(fd);}
}
function rootTrust(name,max=4096){
 return fileBytes(TRUST+'/'+name,0,0o400,max).toString('utf8').trim();
}
function checkedSourcePath(path){
 if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path||
    path.length>4096||!path.startsWith('/home/'))deny();
 if(realpathSync(path)!==path)deny();
 return path;
}
function expectedTree(){
 const dirs=new Set(['','code']),files=new Set(['MANIFEST.json']);
 for(const rel of SOURCE){
  const p='code/'+rel,parts=p.split('/');
  for(let i=1;i<parts.length;i++)dirs.add(parts.slice(0,i).join('/'));
  files.add(p);
 }
 return {dirs,files};
}
function assertExactTree(base,owner){
 const expected=expectedTree(),foundDirs=new Set(),foundFiles=new Set();
 // Never allocate a directory's complete names array from untrusted input.
 // Read one entry at a time with a fixed bound across the complete tree.
 const maxMembers=expected.dirs.size+expected.files.size-1;
 let scanned=0;
 function walk(path,relative){
  dir(path,owner,0o700);
  foundDirs.add(relative);
  const stream=opendirSync(path);
  try{
   for(let entry=stream.readSync();entry!==null;entry=stream.readSync()){
    if(++scanned>maxMembers)deny();
    const name=entry.name;
    if(typeof name!=='string'||!name||name.length>255||
       name==='.'||name==='..')deny();
    const rel=relative?relative+'/'+name:name;
    const item=join(path,name),s=lstatSync(item);
    if(s.uid!==owner||s.isSymbolicLink())deny();
    if(s.isDirectory()){
     if(!expected.dirs.has(rel))deny();
     walk(item,rel);
    }else if(s.isFile()){
     if(!expected.files.has(rel)||(s.mode&0o777)!==0o444||
        s.nlink!==1)deny();
     foundFiles.add(rel);
    }else deny();
   }
  }finally{stream.closeSync();}
 }
 walk(base,'');
 if(foundDirs.size!==expected.dirs.size||
    foundFiles.size!==expected.files.size||
    [...expected.dirs].some(p=>!foundDirs.has(p))||
    [...expected.files].some(p=>!foundFiles.has(p)))deny();
}
/** Source manifest/data validation ONLY; NOT installation authorization. */
export function verifyOwnerStageManifest({raw,head,sha256}={}){
 if(typeof raw!=='string'||Buffer.byteLength(raw)>16384||
    !SHA.test(head||'')||!HASH.test(sha256||'')||
    digest(Buffer.from(raw,'utf8'))!==sha256)deny();
 let m;
 try{m=JSON.parse(raw);}catch{deny();}
 if(!isExact(m,['version','repository','head','installAuthorized',
     'requiredIndependentIssuers','files'])||
    JSON.stringify(m)!==raw||m.version!==1||m.repository!==REPO||
    m.head!==head||m.installAuthorized!==false||
    JSON.stringify(m.requiredIndependentIssuers)!==
      JSON.stringify(['independent-codex','protected-approval'])||
    !Array.isArray(m.files)||m.files.length!==SOURCE.length)deny();
 let sum=0;
 for(let i=0;i<SOURCE.length;i++){
  const f=m.files[i];
  if(!isExact(f,['path','bytes','sha256'])||
     f.path!==SOURCE[i]||!Number.isSafeInteger(f.bytes)||
     f.bytes<1||f.bytes>MAX_FILE||!HASH.test(f.sha256||'')||
     posix.normalize(f.path)!==f.path||
     f.path.includes('..')||f.path.startsWith('/'))deny();
  sum+=f.bytes;
 }
 if(sum>MAX_PACKAGE)deny();
 return Object.freeze({head:m.head,fileCount:m.files.length,
  files:Object.freeze(m.files.map(x=>Object.freeze({...x}))),
  ownerInstallationAuthorized:false});
}
function packPayload(path,owner,head,manifestHash){
 if(owner===0){
  // Only the exact two new, root-owned staging targets; never a caller path.
  if((path!==PENDING&&path!==DEST)||realpathSync(path)!==path)deny();
 }else checkedSourcePath(path);
 assertExactTree(path,owner);
 const manifest=fileBytes(join(path,'MANIFEST.json'),owner,0o444,16384);
 const shape=verifyOwnerStageManifest({
  raw:manifest.toString('utf8'),head,sha256:manifestHash
 });
 let sum=0;
 const data=shape.files.map(row=>{
  const b=fileBytes(join(path,'code',row.path),owner,0o444,MAX_FILE);
  if(b.length!==row.bytes||digest(b)!==row.sha256)deny();
  sum+=b.length;
  return {path:row.path,bytes:b};
 });
 if(sum>MAX_PACKAGE)deny();
 return {head,fileCount:data.length,manifest,files:data};
}
function exclusive(path,bytes){
 const fd=openSync(path,WRITE,0o600);
 try{
  let off=0;
  while(off<bytes.length){
   const n=writeSync(fd,bytes,off,bytes.length-off,off);
   if(n<=0)deny();off+=n;
  }
  fchmodSync(fd,0o444);fsyncSync(fd);
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
     s.size!==bytes.length||(s.mode&0o777)!==0o444)deny();
 }finally{closeSync(fd);}
}
function rootParentTree(base,files){
 const created=new Set([base]);
 for(const rel of files){
  const seg=('code/'+rel).split('/').slice(0,-1);
  let p=base;
  for(const name of seg){
   p=join(p,name);
   if(created.has(p))continue;
   mkdirSync(p,{mode:0o700});rootDir(p,0o700);
   created.add(p);
  }
 }
 return created;
}
function checkOwnerSession(ownerUid=null){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY||
    process.stdin.isTTY!==true||process.stderr.isTTY!==true||
    process.env.SSH_CLIENT!==undefined||
    process.env.SSH_CONNECTION!==undefined||
    (ownerUid!==null&&String(ownerUid)!==process.env.SUDO_UID))deny();
 const self=lstatSync(ENTRY);
 if(!self.isFile()||self.isSymbolicLink()||self.uid!==0||
    self.nlink!==1||(self.mode&0o777)!==0o444)deny();
}
export function stageOwnerApprovedPackOnce(){
 // Reject untrusted/nonroot/mutable checkout invocation BEFORE touching
 // any protected trust directories, signer metadata or root staging paths.
 checkOwnerSession();
 const ancestors=['/','/usr','/usr/local','/usr/local/lib',ROOT,
   '/etc','/etc/mcp-dev-hub',TRUST];
 for(const p of ancestors)rootDir(p,p===TRUST?0o700:null);
 const owner=Number(rootTrust('approved-handoff-uid',16));
 if(!Number.isSafeInteger(owner)||owner<=0)deny();
 checkOwnerSession(owner);
 const head=rootTrust('approved-head',128);
 const hash=rootTrust('approved-pack-digest',128);
 const handoff=rootTrust('approved-handoff-path',4096);
 if(!SHA.test(head)||!HASH.test(hash))deny();
 // Fail BEFORE first root-side effect if anything exists or is incomplete.
 absent(DEST);absent(PENDING);
 const source=packPayload(handoff,owner,head,hash);
 const all=source.files.map(row=>row.path);
 mkdirSync(PENDING,{mode:0o700});rootDir(PENDING,0o700);
 const dirs=rootParentTree(PENDING,all);
 for(const row of source.files)
  exclusive(join(PENDING,'code',row.path),row.bytes);
 exclusive(join(PENDING,'MANIFEST.json'),source.manifest);
 for(const p of [...dirs].sort((a,b)=>b.length-a.length))syncDir(p);
 syncDir(ROOT);
 // Verify every copied file under immutable root-controlled ownership first.
 packPayload(PENDING,0,head,hash);
 renameSync(PENDING,DEST);syncDir(ROOT);
 // One-shot readback, preserving UNKNOWN evidence on any post-rename error.
 packPayload(DEST,0,head,hash);
 return Object.freeze({
  phase:'immutable_source_only_staged_no_operating_authority',
  head,manifestSha256:hash,fileCount:source.fileCount,
  ownerIdentityAuthenticatedByTool:false,
  signingKeysProvisioned:false,reviewIssued:false,
  updaterActivated:false,safeToInstall:false,safeToRetry:false
 });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const r=stageOwnerApprovedPackOnce();
  process.stdout.write(JSON.stringify(r)+'\n');
 }catch{
  process.stderr.write('protected_owner_root_stage_denied_or_unknown\n');
  process.exitCode=1;
 }
}
