// #35 UNINSTALLED fixed root-only issuer code staging primitive.
// The source-only package uses mode-0700 root-only code directories. Signer
// accounts MUST NOT run code from a mutable checkout or be granted access
// to this package. Instead this one-shot root tool copies ONLY the verified
// static import closure to a separate root-owned, non-writable, readable
// issuer-runtime directory. An independent owner-controlled bootstrap must
// authenticate the package before this code can ever be run with root.
import {createHash} from 'node:crypto';
import {constants,closeSync,fchmodSync,fstatSync,fsyncSync,lstatSync,
  mkdirSync,openSync,readFileSync,renameSync,chmodSync,writeSync}
  from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-issuer-stage.mjs';
const INSTALL=ROOT+'/protected-issuer';
const STAGE=ROOT+'/.protected-issuer.pending';
const TRUST='/etc/mcp-dev-hub/protected-update';
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;
const SELECTED=Object.freeze([
  'scripts/protected-update-review-issuer.mjs',
  'scripts/protected-update-approval-issuer.mjs',
  'scripts/protected-update-routine-review-issuer.mjs',
  'scripts/protected-update-routine-approval-issuer.mjs',
  'scripts/protected-update-app-acceptance-approval-issuer.mjs',
  'src/ops/protected-update-bootstrap-issuer.mjs',
  'src/ops/protected-update-routine-issuer.mjs',
  'src/ops/protected-update-approval.mjs',
  'src/ops/protected-update-manifest.mjs',
  'src/ops/protected-update-install-attestation.mjs',
  'src/ops/protected-update-issuer-runtime.mjs',
  'src/ops/protected-update-github-evidence.mjs',
  'src/ops/protected-update-app-acceptance.mjs'
]);
const HASH=/^[a-f0-9]{64}$/;
const deny=()=>{throw Error('protected_issuer_staging_denied_or_unknown');};
const digest=b=>createHash('sha256').update(b).digest('hex');
function dir(path,mode=null){
  const s=lstatSync(path);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||
     (s.mode&0o022)!==0||
     (mode!==null&&(s.mode&0o777)!==mode))deny();
}
function absent(path){
  try{lstatSync(path);deny();}
  catch(e){if(e.code!=='ENOENT')throw e;}
}
function syncDir(path){
  const fd=openSync(path,constants.O_RDONLY|
    constants.O_NOFOLLOW|constants.O_DIRECTORY);
  try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally{closeSync(fd);}
}
function checkedRead(path,mode,size,hash){
  const fd=openSync(path,READ);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
       (st.mode&0o777)!==mode||st.size!==size||
       size<1||size>256*1024)deny();
    const b=readFileSync(fd);
    if(b.length!==size||digest(b)!==hash)deny();
    return b;
  }finally{closeSync(fd);}
}
function exclusiveWrite(path,bytes){
  const fd=openSync(path,WRITE,0o600);
  try{
    let n=0;
    while(n<bytes.length){
      const k=requireWrite(fd,bytes,n);
      n+=k;
    }
    fchmodSync(fd,0o444);
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       s.size!==bytes.length||(s.mode&0o777)!==0o444)deny();
  }finally{closeSync(fd);}
}
function requireWrite(fd,bytes,n){
  const written=writeSync(fd,bytes,n,bytes.length-n,n);
  if(written<=0)deny();
  return written;
}
/** Reviewable static import-closure selection; no dynamic allowlists. */
export function selectFixedIssuerSourceRows(files){
  if(!Array.isArray(files)||files.length<SELECTED.length)deny();
  const rows=SELECTED.map(name=>{
    const matches=files.filter(f=>f?.path===name);
    if(matches.length!==1||
       !Number.isSafeInteger(matches[0].bytes)||
       matches[0].bytes<1||matches[0].bytes>256*1024||
       !HASH.test(matches[0].sha256))deny();
    return Object.freeze({...matches[0]});
  });
  return Object.freeze(rows);
}
function pin(){
  const fd=openSync(TRUST+'/approved-pack-digest',READ);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o400||s.size<1||s.size>128)deny();
    const raw=readFileSync(fd,'utf8').trim();
    if(!HASH.test(raw))deny();
    return raw;
  }finally{closeSync(fd);}
}
export function stagePinnedIssuerRuntimeOnce(){
  if(process.getuid?.()!==0||process.geteuid?.()!==0||
     fileURLToPath(import.meta.url)!==ENTRY||process.argv.length!==2)
    deny();
  for(const p of ['/','/usr','/usr/local','/usr/local/lib',
    ROOT,PACK,PACK+'/code','/etc','/etc/mcp-dev-hub',TRUST])
    dir(p);
  absent(STAGE);absent(INSTALL);
  const approved=pin();
  const pack=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:approved
  });
  if(pack.status!=='source_only_unprivileged_no_go')deny();
  const rows=selectFixedIssuerSourceRows(pack.files);
  mkdirSync(STAGE,{mode:0o700});
  mkdirSync(STAGE+'/code',{mode:0o700});
  mkdirSync(STAGE+'/code/scripts',{mode:0o700,recursive:true});
  mkdirSync(STAGE+'/code/src/ops',{mode:0o700,recursive:true});
  for(const row of rows){
    const bytes=checkedRead(PACK+'/code/'+row.path,0o444,
      row.bytes,row.sha256);
    exclusiveWrite(STAGE+'/code/'+row.path,bytes);
    checkedRead(STAGE+'/code/'+row.path,0o444,
      row.bytes,row.sha256);
  }
  for(const d of [
    STAGE+'/code/scripts',STAGE+'/code/src/ops',
    STAGE+'/code/src',STAGE+'/code',STAGE
  ]){
    chmodSync(d,0o555);
    dir(d,0o555);
    syncDir(d);
  }
  syncDir(ROOT);
  renameSync(STAGE,INSTALL);
  syncDir(ROOT);
  for(const row of rows)checkedRead(
    INSTALL+'/code/'+row.path,0o444,row.bytes,row.sha256
  );
  return Object.freeze({
    state:'issuer_code_staged_not_authorized',files:rows.length,
    privateKeysProvisioned:false,signaturesIssued:false,
    safeToRetry:false
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=stagePinnedIssuerRuntimeOnce();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_issuer_staging_denied_or_unknown\n');
    process.exitCode=1;
  }
}
