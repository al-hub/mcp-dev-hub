// #35: nonprivileged, READ-ONLY OS pre-bootstrap readiness probe.
// No sudo, installation, keys, token, entitlement, or state changes.
// Only the separately authenticated root installer may authorize bootstrap.
// Compares actual protected original bytes with an EXACT immutable Git commit,
// then checks the real root-owned Bubblewrap with controller ESM startup.
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,isAbsolute} from 'node:path';

const ROOT='/usr/local/lib/mcp-dev-hub';
const BWRAP='/usr/bin/bwrap';
const GIT='/usr/bin/git';
const NODE='/usr/bin/node';
const SHA=/^[a-f0-9]{40}$/;
const MAX_BYTES=256*1024;
const FILES=Object.freeze([
  ['ai-github-canary-policy.mjs','src/jobs/ai-github-canary-policy.mjs'],
  ['ai-github-canary.mjs','scripts/ai-github-canary.mjs']
]);
const fail=()=>{throw Error('protected_bootstrap_readiness_denied');};
const digest=b=>createHash('sha256').update(b).digest('hex');

function secureDirectory(path){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
    (st.mode&0o022)!==0)fail();
}
function boundedRead(path){
  const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|
    constants.O_NONBLOCK);
  try{
    const before=fstatSync(fd);
    if(!before.isFile()||before.isSymbolicLink()||before.uid!==0||
      before.nlink!==1||(before.mode&0o777)!==0o555||
      before.size<1||before.size>MAX_BYTES)fail();
    const b=readFileSync(fd);
    const after=fstatSync(fd);
    if(after.dev!==before.dev||after.ino!==before.ino||
       after.size!==before.size||b.length!==before.size)fail();
    return b;
  }finally{closeSync(fd);}
}
function gitBlob(repositoryPath,commit,file){
  const ref=commit+':'+file;
  const tree=spawnSync(GIT,['-C',repositoryPath,'ls-tree',
    '--full-tree',commit,'--',file],{
    encoding:'utf8',shell:false,timeout:15000,maxBuffer:2048
  });
  if(tree.status!==0||tree.error||
    !/^100644 blob [a-f0-9]{40}\t/.test(tree.stdout)||
    tree.stdout.trim().split('\t')[1]!==file)fail();
  const r=spawnSync(GIT,['-C',repositoryPath,'show',ref],{
    shell:false,timeout:15000,maxBuffer:MAX_BYTES+1024,encoding:null
  });
  if(r.status!==0||r.error||!Buffer.isBuffer(r.stdout)||
     r.stdout.length<1||r.stdout.length>MAX_BYTES)fail();
  return r.stdout;
}
/** Pure byte comparison, not OS or reviewer authorization. */
export function matchProtectedBaselinePair({
  actualPolicy,expectedPolicy,actualController,expectedController
}={}){
  for(const b of [actualPolicy,expectedPolicy,actualController,
    expectedController]){
    if(!Buffer.isBuffer(b)||b.length<1||b.length>MAX_BYTES)fail();
  }
  if(!actualPolicy.equals(expectedPolicy)||
     !actualController.equals(expectedController))fail();
  return Object.freeze([
    Object.freeze({name:FILES[0][0],bytes:actualPolicy.length,
      sha256:digest(actualPolicy)}),
    Object.freeze({name:FILES[1][0],bytes:actualController.length,
      sha256:digest(actualController)})
  ]);
}
/** Read-only isolated import: no source command execution or Worker state.
 * Signed root updater performs a separate pinned service/health observation.
 */
export function isolatedProtectedBaselineStartup(){
  const st=lstatSync(BWRAP);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0||(st.mode&0o111)===0)fail();
  const js='try{await import("file://'+ROOT+
    '/ai-github-canary.mjs");process.stdout.write("BASELINE_READY\\n")}'+
    'catch{process.exitCode=23;process.stdout.write("BASELINE_BROKEN\\n")}';
  const r=spawnSync(BWRAP,[
    '--clearenv','--unshare-all','--die-with-parent',
    '--ro-bind','/usr','/usr','--ro-bind','/bin','/bin',
    '--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64',
    '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
    '--dir','/etc','--dir','/home','--chdir','/tmp',
    '--setenv','HOME','/home','--setenv','PATH','/usr/bin:/bin',
    '--setenv','LANG','C.UTF-8',
    '--',NODE,'--input-type=module','-e',js
  ],{
    cwd:'/',shell:false,encoding:'utf8',timeout:15000,
    maxBuffer:4096,env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'},
    stdio:['ignore','pipe','pipe']
  });
  if(r.error||r.signal||r.status!==0||
     r.stdout!=='BASELINE_READY\n')fail();
  return true;
}
/** Nonprivileged gate only. Repository path is read as UNTRUSTED test data;
 * git commit must be independently pinned by an authorized root reviewer.
 * Even if this passes, a user/admin bootstrap remains separately required.
 */
export function inspectExistingProtectedBootstrapBaseline({
  repositoryPath,baselineCommit
}={}){
  if(typeof repositoryPath!=='string'||!isAbsolute(repositoryPath)||
     resolve(repositoryPath)!==repositoryPath||
     typeof baselineCommit!=='string'||!SHA.test(baselineCommit)||
     typeof process.geteuid!=='function'||process.geteuid()===0)fail();
  for(const path of ['/', '/usr','/usr/local','/usr/local/lib',ROOT])
    secureDirectory(path);
  const actual=FILES.map(([name])=>boundedRead(ROOT+'/'+name));
  const expected=FILES.map(([,source])=>
    gitBlob(repositoryPath,baselineCommit,source));
  const files=matchProtectedBaselinePair({
    actualPolicy:actual[0],expectedPolicy:expected[0],
    actualController:actual[1],expectedController:expected[1]
  });
  if(!isolatedProtectedBaselineStartup())fail();
  return Object.freeze({
    status:'original_baseline_and_isolated_startup_confirmed',
    baselineCommit,files,installerAuthorized:false,
    realProtectedUpdates:0
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    if(process.argv.length!==4)fail();
    const result=inspectExistingProtectedBootstrapBaseline({
      repositoryPath:process.argv[2],baselineCommit:process.argv[3]
    });
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_bootstrap_readiness_denied\n');
    process.exitCode=1;
  }
}
