// #35: bounded, non-privileged TESTABLE release-pointer mechanics.
// Not a root updater or a grant of authority. Never execute checkout code as
// root. A separately installed immutable verifier MUST authenticate GitHub,
// independent review, signer, approval, source bytes and ALL path ancestors.
import {createHash} from 'node:crypto';
import {
  constants, chmodSync, closeSync, fchmodSync, fstatSync, fsyncSync, lstatSync,
  mkdirSync, openSync, readFileSync, readdirSync, readlinkSync, renameSync,
  symlinkSync, unlinkSync, writeSync
} from 'node:fs';
import {join, isAbsolute, resolve} from 'node:path';

export const RELEASE_FILES=Object.freeze([
  'ai-github-canary-policy.mjs','ai-github-canary.mjs'
]);
const COMMIT=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const MAX_BYTES=256*1024;
const deny=()=>{throw Error('protected_release_guard_failed');};
const nofollow=constants.O_NOFOLLOW|constants.O_NONBLOCK;
const writeFlags=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

function directory(path,uid) {
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||
    (st.mode&0o022)!==0||(st.mode&0o005)!==0o005||st.uid!==uid)deny();
}
function rootAndVersions(root) {
  if(typeof root!=='string'||!isAbsolute(root)||resolve(root)!==root||
     typeof process.getuid!=='function')deny();
  const uid=process.getuid();
  directory(root,uid);
  directory(join(root,'versions'),uid);
  // The immutable root supervisor must validate ALL ancestors, not this
  // library: a valid current directory alone does not establish trust.
  return uid;
}
function syncDirectory(path) {
  const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try {if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally {closeSync(fd);}
}
function fileBytes(path,owner,expectedBytes,expectedHash) {
  const fd=openSync(path,constants.O_RDONLY|nofollow);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==owner||(st.mode&0o777)!==0o444||
       st.size!==expectedBytes||st.size<1||st.size>MAX_BYTES)deny();
    const bytes=readFileSync(fd);
    if(bytes.length!==expectedBytes||digest(bytes)!==expectedHash)deny();
  }finally{closeSync(fd);}
}
function approvedFiles(files) {
  if(!Array.isArray(files)||files.length!==2)deny();
  const names=files.map(f=>f?.name);
  if(new Set(names).size!==2||
     !RELEASE_FILES.every(name=>names.includes(name)))deny();
  for(const f of files){
    if(Object.keys(f).sort().join(',')!=='bytes,name,sha256'||
       typeof f.sha256!=='string'||!HASH.test(f.sha256)||
       !Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>MAX_BYTES)deny();
  }
  return files;
}
function validCommit(sha) {
  if(typeof sha!=='string'||!COMMIT.test(sha))deny();
  return sha;
}
function releaseDir(root,sha) {
  return join(root,'versions',validCommit(sha));
}
function verifyRelease(root,owner,sha,files) {
  const dir=releaseDir(root,sha);
  directory(dir,owner);
  for(const f of approvedFiles(files))
    fileBytes(join(dir,f.name),owner,f.bytes,f.sha256);
  return dir;
}

function entryExists(path){
  try{return lstatSync(path);}catch(e){
    if(e.code==='ENOENT')return null;
    throw e;
  }
}
/** Pure pre-effect preflight for an approved, fixed two-file release.
 * Existing exact versions are reusable after a verified rollback. A partial
 * stage or mismatched existing version is a blocker BEFORE journal creation.
 */
export function inspectProtectedReleaseStaging(root,{commit,files,contents}={}){
  const owner=rootAndVersions(root);
  validCommit(commit);
  approvedFiles(files);
  if(contents===null||typeof contents!=='object'||
     Array.isArray(contents)||Object.keys(contents).sort().join(',')!==
      RELEASE_FILES.slice().sort().join(','))deny();
  for(const f of files){
    const data=contents[f.name];
    if(!Buffer.isBuffer(data)||data.length!==f.bytes||
       digest(data)!==f.sha256)deny();
  }
  const stage=join(root,'versions','.stage-'+commit);
  if(entryExists(stage))deny(); // unknown/partial: never auto-reclaim
  const published=releaseDir(root,commit);
  if(entryExists(published)){
    verifyRelease(root,owner,commit,files);
    return Object.freeze({commit,existing:true});
  }
  return Object.freeze({commit,existing:false});
}
/** Stage only authenticated bytes from the future immutable root verifier.
 * Crashed/partial stages remain for explicit reconciliation (no auto-delete).
 */
export function stageProtectedRelease(root,{commit,files,contents}={}){
  const inspected=inspectProtectedReleaseStaging(root,{
    commit,files,contents
  });
  if(inspected.existing)
    return Object.freeze({commit,files:files.map(f=>Object.freeze({...f}))});
  const owner=rootAndVersions(root);
  const stage=join(root,'versions','.stage-'+commit);
  mkdirSync(stage,{mode:0o700});
  for(const f of files){
    const data=contents[f.name];
    if(!Buffer.isBuffer(data)||data.length!==f.bytes||
       digest(data)!==f.sha256)deny();
    const fd=openSync(join(stage,f.name),writeFlags,0o444);
    try {
      let written=0;
      while(written<data.length) {
        const n=writeSync(fd,data,written,data.length-written,written);
        if(n<=0)deny();
        written+=n;
      }
      // O_EXCL creation mode is masked by umask; enforce public read-only
      // for the existing non-root Worker, without granting write or exec.
      fchmodSync(fd,0o444);
      fsyncSync(fd);
    }finally{closeSync(fd);}
    fileBytes(join(stage,f.name),owner,f.bytes,f.sha256);
  }
  syncDirectory(stage);
  chmodSync(stage,0o555);
  renameSync(stage,releaseDir(root,commit));
  syncDirectory(join(root,'versions'));
  verifyRelease(root,owner,commit,files);
  return Object.freeze({commit,files:files.map(f=>Object.freeze({...f}))});
}
function currentCommit(root,owner) {
  const path=join(root,'current');
  try {
    const st=lstatSync(path);
    if(!st.isSymbolicLink()||st.uid!==owner)deny();
    const target=readlinkSync(path);
    const m=/^versions\/([a-f0-9]{40})$/.exec(target);
    if(!m)deny();
    return m[1];
  }catch(e){if(e.code==='ENOENT')return null;throw e;}
}
export function inspectProtectedRelease(root,{files}={}){
  const owner=rootAndVersions(root);
  const commit=currentCommit(root,owner);
  if(commit!==null&&files)verifyRelease(root,owner,commit,files);
  return commit;
}
/** Read actual previously installed release metadata, never trust the
 * caller to name the current release's files or supply their old hashes.
 * This is metadata ONLY; pinning all trusted ancestors remains the immutable
 * root bootstrap's responsibility. Refuse any special files or extras.
 */
export function inspectProtectedCurrentSnapshot(root) {
  const owner=rootAndVersions(root);
  const commit=currentCommit(root,owner);
  if(commit===null)deny(); // initial migration needs explicit bootstrap
  const dir=releaseDir(root,commit);
  directory(dir,owner);
  const entries=readdirSync(dir).sort();
  if(entries.length!==RELEASE_FILES.length||
     entries.join('\\0')!==RELEASE_FILES.slice().sort().join('\\0'))deny();
  const files=RELEASE_FILES.map(name=>{
    const fd=openSync(join(dir,name),constants.O_RDONLY|nofollow);
    try{
      const st=fstatSync(fd);
      if(!st.isFile()||st.uid!==owner||
         (st.mode&0o777)!==0o444||st.size<1||st.size>MAX_BYTES)deny();
      const bytes=readFileSync(fd);
      if(bytes.length!==st.size)deny();
      return Object.freeze({
        name,bytes:st.size,sha256:digest(bytes)
      });
    }finally{closeSync(fd);}
  });
  return Object.freeze({commit,files:Object.freeze(files)});
}
/** Compare-and-swap one symlink, never two live source files.
 * Caller must have durably persisted switch_pending BEFORE invocation and
 * independently verified approval, old/new bytes, service consequences.
 */
export function switchProtectedRelease(root,{
  expectedCommit=null,nextCommit,nextFiles
}={}){
  const owner=rootAndVersions(root);
  if(expectedCommit!==null)validCommit(expectedCommit);
  validCommit(nextCommit);
  if(expectedCommit===nextCommit)deny();
  approvedFiles(nextFiles);
  const lock=join(root,'.switch.lock');
  const lockFd=openSync(lock,writeFlags,0o600);
  try{
    fsyncSync(lockFd);
    syncDirectory(root);
    if(currentCommit(root,owner)!==expectedCommit)deny();
    verifyRelease(root,owner,nextCommit,nextFiles);
    const pending=join(root,'.next-'+nextCommit);
    symlinkSync('versions/'+nextCommit,pending);
    syncDirectory(root);
    if(currentCommit(root)!==expectedCommit)deny();
    renameSync(pending,join(root,'current'));
    syncDirectory(root);
    if(currentCommit(root,owner)!==nextCommit)deny();
    // This is pointer switching, NOT service-health verification.
    return Object.freeze({from:expectedCommit,to:nextCommit});
  }finally {
    closeSync(lockFd);
    unlinkSync(lock);
    syncDirectory(root);
  }
}
// A failure before the atomic rename leaves a .next-* entry, requiring a
// trusted reconciliation. A lost response AFTER rename must query current
// pointer and journal by operation ID, never blindly switch again.
