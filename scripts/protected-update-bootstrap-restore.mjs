// #35: fixed root-only emergency original-controller restoration.
// Deliberately NOT an ordinary Worker sudo command. Requires a separate
// administrator-authorized local recovery session and pinned OS root trust.
// Never auto-recover an unknown or newer source revision.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {verifyProtectedBootstrapPack}
  from './protected-update-bootstrap-pack.mjs';
import {restoreOriginalControllerCandidate}
  from '../src/ops/protected-update-bootstrap-migration.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const PACK=ROOT+'/protected-updater';
const ENTRY=PACK+'/code/scripts/protected-update-bootstrap-restore.mjs';
const TRUST='/etc/mcp-dev-hub/protected-update';
const EXPECTED=['ai-github-canary-policy.mjs','ai-github-canary.mjs'];
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const fail=()=>{throw Error('protected_bootstrap_restore_denied');};
const digest=b=>createHash('sha256').update(b).digest('hex');
function requireRootDir(path){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
     (st.mode&0o022)!==0)fail();
}
function readTrust(name,maxBytes=4096){
  const fd=openSync(TRUST+'/'+name,constants.O_RDONLY|
    constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o400||s.size<1||s.size>maxBytes)fail();
    const b=readFileSync(fd);
    if(b.length!==s.size)fail();
    return b.toString('utf8').trim();
  }finally{closeSync(fd);}
}
export function validatePinnedOriginalHashes(raw){
  let arr;
  try{arr=JSON.parse(raw);}catch{fail();}
  if(JSON.stringify(arr)!==raw||!Array.isArray(arr)||
     arr.length!==2)fail();
  const hashes={};
  for(let i=0;i<EXPECTED.length;i++){
    const f=arr[i];
    if(!f||Object.keys(f).sort().join(',')!=='bytes,name,sha256'||
       f.name!==EXPECTED[i]||
       !Number.isSafeInteger(f.bytes)||f.bytes<1||f.bytes>256*1024||
       !HASH.test(f.sha256))fail();
    hashes[f.name]=f.sha256;
  }
  return Object.freeze(hashes);
}
/** Run only from reviewed root-owned installed code, not a source checkout.
 * Note this restores JUST the previous flat controller: it does not
 * remove preserved version/journal data, or assert live Worker health.
 */
export function restoreProtectedOriginalFixedRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
     process.argv.length!==2||fileURLToPath(import.meta.url)!==ENTRY)
    fail();
  for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
    PACK,PACK+'/code',PACK+'/code/scripts','/etc','/etc/mcp-dev-hub',TRUST])
    requireRootDir(p);
  const pinnedDigest=readTrust('approved-pack-digest',128);
  const baselineCommit=readTrust('baseline-commit',128);
  if(!HASH.test(pinnedDigest)||!SHA.test(baselineCommit))fail();
  const verified=verifyProtectedBootstrapPack({
    outputPath:PACK,expectedManifestSha256:pinnedDigest
  });
  if(verified.status!=='source_only_unprivileged_no_go')fail();
  const wrapper=verified.files.find(
    f=>f.path==='scripts/protected-update-controller-wrapper.mjs');
  if(!wrapper||!HASH.test(wrapper.sha256))fail();
  const originalHashes=validatePinnedOriginalHashes(
    readTrust('baseline-files.json')
  );
  const result=restoreOriginalControllerCandidate({
    root:ROOT,baselineCommit,originalHashes,
    expectedWrapperSha256:wrapper.sha256
  });
  if(result.phase!=='original_controller_restored')fail();
  return Object.freeze({
    phase:'original_controller_restored_pending_operator_health',
    baselineCommit,safeToRetry:false
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=restoreProtectedOriginalFixedRoot();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_bootstrap_restore_denied_or_unknown\n');
    process.exitCode=1;
  }
}
