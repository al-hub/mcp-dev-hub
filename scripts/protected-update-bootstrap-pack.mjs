// #35: nonprivileged, reproducible source handoff for ONE reviewed bootstrap.
// This never installs, signs, elevates, enables sudo or executes bundled code.
// The returned fingerprint is a CHECKSUM, not a trusted review or signature.
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  chmodSync,closeSync,constants,existsSync,fstatSync,lstatSync,mkdirSync,
  openSync,readFileSync,readdirSync,realpathSync,writeFileSync
} from 'node:fs';
import {dirname,isAbsolute,join,relative,resolve,sep} from 'node:path';
import {fileURLToPath} from 'node:url';

const REPO='al-hub/mcp-dev-hub';
const SHA=/^[a-f0-9]{40}$/;
const HASH=/^[a-f0-9]{64}$/;
const MAX_FILE=256*1024;
const MAX_PACKAGE=2*1024*1024;
const SOURCE=Object.freeze([
  'scripts/protected-update-bootstrap-entry.mjs',
  'scripts/reviewer-app-trusted-preflight.mjs',
  'scripts/reviewer-app-trusted-publish.mjs',
  'scripts/protected-update-codex-receipt.mjs',
  'scripts/protected-update-os-activate.mjs',
  'scripts/protected-update-issuer-provision.mjs',
  'scripts/protected-update-issuer-stage.mjs',
  'scripts/protected-update-issuer-collect.mjs',
  'scripts/protected-update-review-issuer.mjs',
  'scripts/protected-update-approval-issuer.mjs',
  'scripts/protected-update-routine-review-issuer.mjs',
  'scripts/protected-update-routine-approval-issuer.mjs',
  'scripts/protected-update-bootstrap-restore.mjs',
  'scripts/protected-update-bootstrap-pack.mjs',
  'scripts/protected-update-controller-wrapper.mjs',
  'scripts/protected-update-root-apply.mjs',
  'scripts/protected-update-root-reconcile.mjs',
  'src/jobs/github-app-review-publisher.mjs',
  'src/jobs/github-app-publication-fence.mjs',
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
  'src/ops/protected-update-issuer-runtime.mjs',
  'src/ops/protected-update-legacy-capture.mjs',
  'src/ops/protected-update-manifest.mjs',
  'src/ops/protected-update-reconcile.mjs',
  'src/ops/protected-update-release-pointer.mjs',
  'src/ops/protected-update-request.mjs',
  'src/ops/protected-update-routine-issuer.mjs',
  'src/ops/protected-update-routine-collection.mjs',
  'src/ops/protected-update-root-evidence.mjs',
  'src/ops/protected-update-root-layout.mjs',
  'src/ops/protected-update-root-preflight.mjs',
  'src/ops/protected-update-sudo-policy.mjs',
  'src/ops/protected-update-transaction.mjs'
]);
const deny=()=>{throw Error('protected_bootstrap_pack_denied');};
const digest=b=>createHash('sha256').update(b).digest('hex');
function exact(o,keys){
  return o!==null&&typeof o==='object'&&!Array.isArray(o)&&
    Object.keys(o).length===keys.length&&
    keys.every(k=>Object.hasOwn(o,k));
}
function checkedPath(path){
  if(typeof path!=='string'||!isAbsolute(path)||resolve(path)!==path||
     path.length>4096)deny();
  return path;
}
function git(cwd,args,maxBuffer=MAX_PACKAGE){
  const r=spawnSync('git',args,{
    cwd,encoding:null,shell:false,timeout:20000,maxBuffer
  });
  if(r.error||r.status!==0||r.signal||!Buffer.isBuffer(r.stdout))deny();
  return r.stdout;
}
function commitBytes(repo,sha,path){
  // Git objects, not mutable checkout files; never execute these bytes.
  const tree=git(repo,['ls-tree','--full-tree',sha,'--',path],2048)
    .toString('utf8').trim();
  if(!/^100644 blob [a-f0-9]{40}\t/.test(tree)||
     tree.split('\t')[1]!==path)deny();
  const bytes=git(repo,['show',sha+':'+path],MAX_FILE+1024);
  if(bytes.length<1||bytes.length>MAX_FILE)deny();
  return bytes;
}
function checkedSource(repo,sha){
  checkedPath(repo);
  if(typeof sha!=='string'||!SHA.test(sha))deny();
  if(realpathSync(repo)!==repo)deny();
  if(git(repo,['rev-parse','HEAD'],1024).toString('utf8').trim()!==sha)
    deny();
  if(git(repo,['status','--porcelain'],8192).length!==0)deny();
}
function writeExclusive(path,bytes,mode){
  const fd=openSync(path,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{
    writeFileSync(fd,bytes);
    const st=fstatSync(fd);
    if(!st.isFile()||st.nlink!==1||st.size!==bytes.length)deny();
  }finally{closeSync(fd);}
  chmodSync(path,mode);
}
function makeParent(root,relpath){
  const parts=relpath.split('/').slice(0,-1);
  let path=root;
  for(const p of parts){
    path=join(path,p);
    if(!existsSync(path))mkdirSync(path,{mode:0o700});
    const st=lstatSync(path);
    if(!st.isDirectory()||st.isSymbolicLink()||
       (st.mode&0o777)!==0o700)deny();
  }
}
function readBoundedPackFile(path,owner,maxBytes){
  let fd;
  try{
    fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|
      constants.O_NONBLOCK);
    const before=fstatSync(fd);
    if(!before.isFile()||before.uid!==owner||before.nlink!==1||
       (before.mode&0o777)!==0o444||
       before.size<1||before.size>maxBytes)deny();
    const bytes=readFileSync(fd);
    const after=fstatSync(fd);
    if(bytes.length!==before.size||after.dev!==before.dev||
       after.ino!==before.ino||after.size!==before.size||
       after.mtimeMs!==before.mtimeMs)deny();
    return bytes;
  }catch{deny();}
  finally{if(fd!==undefined)closeSync(fd);}
}
function expectedTree(){
  const dirs=new Set(['','code']);
  const paths=['MANIFEST.json'];
  for(const p of SOURCE){
    const parts=('code/'+p).split('/');
    for(let i=1;i<parts.length;i++)
      dirs.add(parts.slice(0,i).join('/'));
    paths.push('code/'+p);
  }
  return {dirs,paths:new Set(paths)};
}
function checkDir(path,mode,owner){
  const s=lstatSync(path);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==owner||
     (s.mode&0o777)!==mode)deny();
}
function treeContents(root,owner){
  const result=[];
  function walk(dir,rel){
    checkDir(dir,0o700,owner);
    for(const name of readdirSync(dir)){
      const p=join(dir,name),r=rel?rel+'/'+name:name,s=lstatSync(p);
      if(s.isSymbolicLink()||s.uid!==owner||s.nlink<1||
         !(s.isFile()||s.isDirectory()))deny();
      result.push({path:r,isDir:s.isDirectory(),mode:s.mode&0o777});
      if(s.isDirectory())walk(p,r);
    }
  }
  walk(root,'');
  return result;
}
/** Build only from a clean detached/checksummed exact Git commit. Caller
 * chooses a NEW private output directory, which is never auto-replaced.
 * Missing signature issuers are deliberately NOT generated or substituted.
 */
export function buildProtectedBootstrapPack({repositoryPath,head,outputPath}={}){
  checkedSource(repositoryPath,head);
  checkedPath(outputPath);
  if(existsSync(outputPath))deny();
  const sources=SOURCE.map(path=>({path,bytes:commitBytes(repositoryPath,head,path)}));
  if(sources.reduce((sum,f)=>sum+f.bytes.length,0)>MAX_PACKAGE)deny();
  mkdirSync(outputPath,{mode:0o700});
  chmodSync(outputPath,0o700);
  mkdirSync(join(outputPath,'code'),{mode:0o700});
  for(const f of sources){
    const rel='code/'+f.path;
    makeParent(outputPath,rel);
    writeExclusive(join(outputPath,rel),f.bytes,0o444);
  }
  const manifest={
    version:1,repository:REPO,head,
    installAuthorized:false,
    requiredIndependentIssuers:['independent-codex','protected-approval'],
    files:sources.map(({path,bytes})=>({
      path,bytes:bytes.length,sha256:digest(bytes)
    }))
  };
  const raw=JSON.stringify(manifest);
  writeExclusive(join(outputPath,'MANIFEST.json'),Buffer.from(raw),0o444);
  const manifestSha256=digest(Buffer.from(raw));
  verifyProtectedBootstrapPack({outputPath,expectedManifestSha256:manifestSha256});
  return Object.freeze({head,manifestSha256,fileCount:sources.length,
    status:'source_only_unprivileged_no_go'});
}
/** Read-only integrity check. A checksum obtained from the same mutable
 * package is NOT independent authority; expectedManifestSha256 MUST come
 * from an external trusted review/installation approval channel.
 */
export function verifyProtectedBootstrapPack({outputPath,expectedManifestSha256}={}){
  checkedPath(outputPath);
  if(typeof expectedManifestSha256!=='string'||
     !HASH.test(expectedManifestSha256))deny();
  const owner=process.getuid?.();
  if(!Number.isInteger(owner)||realpathSync(outputPath)!==outputPath)deny();
  const tree=treeContents(outputPath,owner),expected=expectedTree();
  if(tree.length!==expected.dirs.size-1+expected.paths.size)deny();
  for(const item of tree){
    if(item.isDir){
      if(!expected.dirs.has(item.path)||item.mode!==0o700)deny();
    }else if(!expected.paths.has(item.path)||item.mode!==0o444)deny();
  }
  const manifestPath=join(outputPath,'MANIFEST.json');
  const manifestBytes=readBoundedPackFile(manifestPath,owner,8192);
  if(digest(manifestBytes)!==expectedManifestSha256)deny();
  let m;
  try{m=JSON.parse(manifestBytes.toString('utf8'));}catch{deny();}
  if(!exact(m,['version','repository','head','installAuthorized',
    'requiredIndependentIssuers','files'])||
     JSON.stringify(m)!==manifestBytes.toString('utf8')||
     m.version!==1||m.repository!==REPO||!SHA.test(m.head)||
     m.installAuthorized!==false||
     JSON.stringify(m.requiredIndependentIssuers)!==
       JSON.stringify(['independent-codex','protected-approval'])||
     !Array.isArray(m.files)||m.files.length!==SOURCE.length)deny();
  let total=0;
  for(let i=0;i<SOURCE.length;i++){
    const f=m.files[i];
    if(!exact(f,['path','bytes','sha256'])||f.path!==SOURCE[i]||
       !Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>MAX_FILE||
       typeof f.sha256!=='string'||!HASH.test(f.sha256))deny();
    const p=join(outputPath,'code',f.path),st=lstatSync(p);
    if(!st.isFile()||st.isSymbolicLink()||st.uid!==owner||
       st.nlink!==1||(st.mode&0o777)!==0o444||st.size!==f.bytes)
      deny();
    const bytes=readBoundedPackFile(p,owner,MAX_FILE);
    if(bytes.length!==f.bytes||digest(bytes)!==f.sha256)deny();
    total+=bytes.length;
  }
  if(total>MAX_PACKAGE)deny();
  return Object.freeze({head:m.head,manifestSha256:expectedManifestSha256,
    fileCount:m.files.length,
    files:Object.freeze(m.files.map(f=>Object.freeze({...f}))),
    status:'source_only_unprivileged_no_go'});
}
export const PROTECTED_BOOTSTRAP_FILES=SOURCE;
if(process.argv[1]&&fileURLToPath(import.meta.url)===resolve(process.argv[1])){
  try{
    const [op,repo,head,out,digestValue]=process.argv.slice(2);
    let result;
    if(op==='build'&&process.argv.length===6)
      result=buildProtectedBootstrapPack({repositoryPath:repo,head,outputPath:out});
    else if(op==='verify'&&process.argv.length===5)
      result=verifyProtectedBootstrapPack({outputPath:repo,
        expectedManifestSha256:head});
    else deny();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_bootstrap_pack_denied\n');
    process.exitCode=1;
  }
}
