// #35: synthetic-testable original-file migration + verified restore.
// NOT an installed root entrypoint, signed issuer or permission grant.
// A separately reviewed, immutable, fixed-path root bootstrap MUST authenticate
// the baseline GitHub commit, the exact original bytes, the reviewed wrapper
// digest, all ancestor directories and root identity BEFORE using this module.
import {createHash} from 'node:crypto';
import {
  chmodSync,closeSync,constants,fchmodSync,fstatSync,fsyncSync,lstatSync,
  mkdirSync,openSync,readFileSync,readdirSync,renameSync,writeFileSync
} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {captureLegacyProtectedPair} from './protected-update-legacy-capture.mjs';
import {
  RELEASE_FILES,inspectProtectedCurrentSnapshot,stageProtectedRelease,
  switchProtectedRelease
} from './protected-update-release-pointer.mjs';

const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const MAX_WRAPPER=256*1024;
const deny=()=>{throw Error('protected_bootstrap_migration_denied');};
const digest=data=>createHash('sha256').update(data).digest('hex');
const writeFlags=constants.O_WRONLY|constants.O_CREAT|
  constants.O_EXCL|constants.O_NOFOLLOW;
const readFlags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;

function exactFiles(a,b){
  return Array.isArray(a)&&Array.isArray(b)&&a.length===2&&b.length===2&&
    RELEASE_FILES.every(name=>{
      const x=a.find(f=>f?.name===name),y=b.find(f=>f?.name===name);
      return x&&y&&x.bytes===y.bytes&&x.sha256===y.sha256;
    });
}
function nonExisting(path){
  try{lstatSync(path);deny();}catch(e){if(e.code!=='ENOENT')throw e;}
}
function directory(path,uid,mode=null){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==uid||
     (st.mode&0o022)!==0||(mode!==null&&(st.mode&0o777)!==mode))deny();
}
function fsyncDir(path){
  const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally{closeSync(fd);}
}
function readChecked(path,owner,mode,maxSize,expectedHash){
  const fd=openSync(path,readFlags);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==owner||(st.mode&0o777)!==mode||
       st.nlink!==1||st.size<1||st.size>maxSize)deny();
    const bytes=readFileSync(fd);
    if(bytes.length!==st.size||digest(bytes)!==expectedHash)deny();
    return bytes;
  }finally{closeSync(fd);}
}
function writeVerified(path,bytes,mode){
  const fd=openSync(path,writeFlags,0o600);
  try{
    let offset=0;
    while(offset<bytes.length){
      const n=writeFileSync; // do not trust a partial write
      // writeFileSync(fd) on Node handles all bytes, including EINTR.
      n(fd,bytes.subarray(offset)); offset=bytes.length;
    }
    fchmodSync(fd,mode);
    fsyncSync(fd);
    const st=fstatSync(fd);
    if(!st.isFile()||st.nlink!==1||st.size!==bytes.length||
       (st.mode&0o777)!==mode)deny();
  }finally{closeSync(fd);}
}
function corePreflight({root,baselineCommit,expectedLegacyFiles,
  wrapperBytes,wrapperSha256}={}){
  if(typeof root!=='string'||!isAbsolute(root)||resolve(root)!==root||
     typeof process.geteuid!=='function'||!SHA.test(baselineCommit||'')||
     !Buffer.isBuffer(wrapperBytes)||wrapperBytes.length<1||
     wrapperBytes.length>MAX_WRAPPER||typeof wrapperSha256!=='string'||
     !HASH.test(wrapperSha256)||digest(wrapperBytes)!==wrapperSha256)deny();
  const owner=process.geteuid();
  directory(root,owner);
  for(const entry of ['versions','current','.switch.lock',
    '.bootstrap-original','.bootstrap-wrapper-pending'])
    nonExisting(join(root,entry));
  const captured=captureLegacyProtectedPair(root);
  if(!exactFiles(captured.files,expectedLegacyFiles))deny();
  return {owner,captured};
}
/** Exposed only for unprivileged synthetic fixture testing. An immutable root
 * entrypoint must hardcode the OS root/trust paths and establish independently
 * authenticated commit/hash/wrapper evidence, never pass Issue-sourced fields.
 *
 * Every original byte is written to a private recovery snapshot and checked
 * BEFORE replacing the live flat controller atomically. An interrupted stage
 * is left intact for human/trusted reconciliation, never silently retried.
 */
export function migrateProtectedOriginalPairCandidate(args={}){
  const {root,baselineCommit,expectedLegacyFiles,
    wrapperBytes,wrapperSha256}=args;
  const {owner,captured}=corePreflight(args);
  const backup=join(root,'.bootstrap-original');
  mkdirSync(backup,{mode:0o700});chmodSync(backup,0o700);
  for(const name of RELEASE_FILES){
    const bytes=captured.contents[name],sha=digest(bytes);
    const dest=join(backup,name);
    writeVerified(dest,bytes,0o400);
    readChecked(dest,owner,0o400,256*1024,sha);
  }
  fsyncDir(backup);fsyncDir(root);
  // A partial stage or crash is preserved. NEVER remove an uncertain backup.
  const versions=join(root,'versions');
  mkdirSync(versions,{mode:0o755});chmodSync(versions,0o755);
  stageProtectedRelease(root,{
    commit:baselineCommit,files:captured.files,contents:captured.contents
  });
  switchProtectedRelease(root,{
    expectedCommit:null,nextCommit:baselineCommit,nextFiles:captured.files
  });
  const snap=inspectProtectedCurrentSnapshot(root);
  if(snap.commit!==baselineCommit||
     !exactFiles(snap.files,captured.files))deny();
  // Do not alter live policy; the versioned controller resolves its sibling
  // policy at the same versioned path after the reviewed wrapper launches.
  const pending=join(root,'.bootstrap-wrapper-pending');
  writeVerified(pending,wrapperBytes,0o555);
  readChecked(pending,owner,0o555,MAX_WRAPPER,wrapperSha256);
  fsyncDir(root);
  renameSync(pending,join(root,'ai-github-canary.mjs'));
  fsyncDir(root);
  readChecked(join(root,'ai-github-canary.mjs'),owner,0o555,
    MAX_WRAPPER,wrapperSha256);
  return Object.freeze({
    phase:'migrated_pending_live_health',
    baselineCommit,originalHashes:Object.freeze(Object.fromEntries(
      captured.files.map(f=>[f.name,f.sha256])
    )),
    safeToRetry:false
  });
}
/** Exact restore of the original controller, preserving both original bytes.
 * This is a testable recovery primitive, NOT authorization to perform it.
 * Requires the original version still active; if a newer version runs,
 * other updater/journal health checks must execute before any restore.
 */
export function restoreOriginalControllerCandidate({
  root,baselineCommit,originalHashes,expectedWrapperSha256
}={}){
  if(typeof root!=='string'||!isAbsolute(root)||resolve(root)!==root||
     typeof process.geteuid!=='function'||!SHA.test(baselineCommit||'')||
     typeof expectedWrapperSha256!=='string'||
     !HASH.test(expectedWrapperSha256)||
     !originalHashes||Object.keys(originalHashes).sort().join(',')!==
       RELEASE_FILES.slice().sort().join(','))deny();
  const owner=process.geteuid();directory(root,owner);
  const snap=inspectProtectedCurrentSnapshot(root);
  if(snap.commit!==baselineCommit||
     !RELEASE_FILES.every(name=>
       snap.files.some(f=>f.name===name&&
         f.sha256===originalHashes[name])))deny();
  const backup=join(root,'.bootstrap-original');
  directory(backup,owner,0o700);
  if(readdirSync(backup).slice().sort().join(',')!==
     RELEASE_FILES.slice().sort().join(','))deny();
  readChecked(join(root,'ai-github-canary.mjs'),owner,0o555,
    MAX_WRAPPER,expectedWrapperSha256);
  const bytes=readChecked(join(backup,'ai-github-canary.mjs'),owner,
    0o400,256*1024,originalHashes['ai-github-canary.mjs']);
  readChecked(join(backup,'ai-github-canary-policy.mjs'),owner,
    0o400,256*1024,originalHashes['ai-github-canary-policy.mjs']);
  const staged=join(root,'.bootstrap-restore-pending');
  nonExisting(staged);
  writeVerified(staged,bytes,0o555);
  readChecked(staged,owner,0o555,256*1024,
    originalHashes['ai-github-canary.mjs']);
  fsyncDir(root);
  renameSync(staged,join(root,'ai-github-canary.mjs'));
  fsyncDir(root);
  readChecked(join(root,'ai-github-canary.mjs'),owner,0o555,
    256*1024,originalHashes['ai-github-canary.mjs']);
  return Object.freeze({phase:'original_controller_restored',
    safeToRetry:false});
}
