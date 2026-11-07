// #35: ONE-SHOT, root-only, fixed-path protected updater activation.
// This is a candidate for INDEPENDENT PRIVILEGED REVIEW, not an operating
// installer grant. Only run after one separately approved local administrator
// session has copied an externally pinned source bundle to a root-owned,
// non-user-writable location and installed separately operated signer keys.
//
// Never invoke this script with sudo from an untrusted checkout. No dynamic
// code paths, executable names, sudo rules, shell, keys or service names.
import {constants,closeSync,fchmodSync,fstatSync,fsyncSync,lstatSync,
  mkdirSync,openSync,readFileSync,renameSync,writeSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
import {assertFixedOperationalIssuerIsolation}
  from '../src/ops/protected-update-issuer-boundary.mjs';
import {renderFixedProtectedSudoPolicy}
  from '../src/ops/protected-update-sudo-policy.mjs';
import {bootstrapOneShotFixedRoot}
  from './protected-update-bootstrap-entry.mjs';
import {restoreProtectedOriginalFixedRoot}
  from './protected-update-bootstrap-restore.mjs';
import {inspectProtectedCurrentSnapshot}
  from '../src/ops/protected-update-release-pointer.mjs';
import {observeProtectedWorkerHealth}
  from '../src/ops/protected-update-health-probe.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const ENTRY=ROOT+'/protected-updater/code/scripts/protected-update-os-activate.mjs';
const STATE='/var/lib/mcp-dev-hub/protected-update';
const TRUST='/etc/mcp-dev-hub/protected-update';
const SUDO_DIR='/etc/sudoers.d';
const SUDO_NAME='mcp-dev-hub-protected-update';
const SUDO=SUDO_DIR+'/'+SUDO_NAME;
const STAGE=SUDO_DIR+'/.'+SUDO_NAME+'.stage';
const VISUDO='/usr/sbin/visudo';
const GETENT='/usr/bin/getent';
const deny=()=>{throw Error('protected_os_activation_denied_or_unknown');};
const READ=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const WRITE=constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|
  constants.O_NOFOLLOW;

function exactRoot(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0||
    fileURLToPath(import.meta.url)!==ENTRY||
    process.argv.length!==2)deny();
}
function realDirectory(path,privateMode=null){
  const st=lstatSync(path);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==0||
    (st.mode&0o022)!==0||
    (privateMode!==null&&(st.mode&0o777)!==privateMode))deny();
}
function absent(path){
  try{lstatSync(path);deny();}catch(e){
    if(e.code!=='ENOENT')throw e;
  }
}
function fsyncDir(path){
  const fd=openSync(path,constants.O_RDONLY|constants.O_DIRECTORY|
    constants.O_NOFOLLOW);
  try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally{closeSync(fd);}
}
function rootTrustFile(name,maxBytes=96){
  const fd=openSync(TRUST+'/'+name,READ);
  try{
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==0||st.nlink!==1||
      (st.mode&0o777)!==0o400||st.size<1||st.size>maxBytes)deny();
    const b=readFileSync(fd);
    if(b.length!==st.size)deny();
    return b.toString('utf8').trim();
  }finally{closeSync(fd);}
}
function roleNumber(name,allowZero=false){
  const raw=rootTrustFile(name);
  if(!/^[0-9]{1,9}$/.test(raw))deny();
  const n=Number(raw);
  if(!Number.isSafeInteger(n)||(!allowZero&&n===0))deny();
  return n;
}
function workerAccount(){
  const name=rootTrustFile('worker-account');
  const policy=renderFixedProtectedSudoPolicy({workerAccount:name});
  const result=spawnSync(GETENT,['passwd',name],{
    encoding:'utf8',shell:false,timeout:8000,maxBuffer:2048,
    stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin'}
  });
  if(result.error||result.signal||result.status!==0||
     typeof result.stdout!=='string')deny();
  const rows=result.stdout.trim().split('\n');
  if(rows.length!==1)deny();
  const cols=rows[0].split(':');
  if(cols.length!==7||cols[0]!==name||
     cols[2]!==String(roleNumber('worker-uid'))||
     cols[3]!==String(roleNumber('worker-gid')))deny();
  return policy;
}
/** Node's getgroups() may include the effective GID even after
 * setgroups([]); reject any other supplementary group before child spawn.
 * This pure guard is never sufficient without the actual OS call.
 */
export function assertNoResidualSupplementaryGroups({actual,expected}={}){
  if(!Array.isArray(actual)||actual.length>1||
     !Number.isSafeInteger(expected)||expected!==0||
     actual.some(g=>!Number.isSafeInteger(g)||g!==expected))deny();
  return true;
}
function dropRootSupplementaryGroupsBeforeHealth(){
  if(process.getuid?.()!==0||process.geteuid?.()!==0||
     process.getegid?.()!==0||
     typeof process.setgroups!=='function'||
     typeof process.getgroups!=='function')deny();
  try{process.setgroups([]);}catch{deny();}
  assertNoResidualSupplementaryGroups({
    actual:process.getgroups(),expected:process.getegid()
  });
}
/** Pure admission gate, unit tested, no OS changes. */
export function validateFixedActivationEvidence({
  bootstrapPhase,baselineCommit,health,policy
}={}){
  if(bootstrapPhase!=='migrated_pending_live_health'||
     typeof baselineCommit!=='string'||!/^[0-9a-f]{40}$/.test(baselineCommit)||
     health!==true||!policy||policy.installAuthorized!==false||
     policy.rootOwned!==true||policy.mode!==0o440||
     !Array.isArray(policy.allowedCommands)||
     policy.allowedCommands.length!==2||
     policy.unrestrictedSudo!==false)deny();
  return Object.freeze({phase:'ready_for_sudo_rule_activation',
    baselineCommit,safeToRetry:false});
}
function writeRootPolicy(policy){
  realDirectory(SUDO_DIR);
  absent(SUDO);
  absent(STAGE);
  const bytes=Buffer.from(policy.text,'utf8');
  if(bytes.length<50||bytes.length>2048)deny();
  const fd=openSync(STAGE,WRITE,0o440);
  try{
    let n=0;
    while(n<bytes.length){
      const w=writeSync(fd,bytes,n,bytes.length-n,n);
      if(w<=0)deny();
      n+=w;
    }
    fchmodSync(fd,0o440);
    fsyncSync(fd);
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o440||s.size!==bytes.length)deny();
  }finally{closeSync(fd);}
  fsyncDir(SUDO_DIR);
  const checked=spawnSync(VISUDO,['-cf',STAGE],{
    shell:false,timeout:10000,maxBuffer:2048,
    encoding:'utf8',stdio:['ignore','pipe','pipe'],
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LANG:'C'}
  });
  if(checked.error||checked.signal||checked.status!==0)deny();
  renameSync(STAGE,SUDO);
  fsyncDir(SUDO_DIR);
  const verified=spawnSync(VISUDO,['-cf',SUDO],{
    shell:false,timeout:10000,maxBuffer:2048,
    encoding:'utf8',stdio:['ignore','pipe','pipe'],
    env:{PATH:'/usr/sbin:/usr/bin:/sbin:/bin',LANG:'C'}
  });
  if(verified.error||verified.signal||verified.status!==0)deny();
}
/** This executes ONLY after trusted root staging and issuer key isolation.
 * Unambiguous unhealthy baseline: restore old controller, preserving all
 * evidence, never replay unknown operations or delete backups/journals.
 */
export async function activateProtectedOSOnce(){
  exactRoot();
  dropRootSupplementaryGroupsBeforeHealth();
  for(const p of ['/','/usr','/usr/local','/usr/local/lib',ROOT,
    '/etc','/etc/mcp-dev-hub',TRUST,'/var','/var/lib',SUDO_DIR])
    realDirectory(p);
  assertFixedOperationalIssuerIsolation();
  const policy=workerAccount();
  absent(SUDO);absent(STAGE);
  realDirectory('/var/lib');
  try{mkdirSync('/var/lib/mcp-dev-hub',{mode:0o700});}
  catch(e){if(e.code!=='EEXIST')throw e;}
  realDirectory('/var/lib/mcp-dev-hub');
  absent(STATE);
  mkdirSync(STATE,{mode:0o700});
  fsyncDir('/var/lib/mcp-dev-hub');
  realDirectory(STATE,0o700);
  // All root-issued signatures, exact source pack, GH CI/protection and
  // reviewer provenance must be checked by the fixed bootstrap entry before
  // it makes any original-controller change.
  const boot=await bootstrapOneShotFixedRoot();
  if(boot.phase!=='migrated_pending_live_health')deny();
  const snapshot=inspectProtectedCurrentSnapshot(ROOT);
  if(snapshot.commit!==boot.baselineCommit)deny();
  const pinnedUid=roleNumber('worker-uid');
  const pinnedGid=roleNumber('worker-gid',true);
  const expected=Object.fromEntries(snapshot.files.map(f=>[f.name,f.sha256]));
  let health;
  try{health=observeProtectedWorkerHealth({
    pinnedWorkerUid:pinnedUid,pinnedWorkerGid:pinnedGid,
    expectedCommit:boot.baselineCommit,expectedHashes:expected
  });}catch{health=null;}
  // A known negative may safely restore exactly the previously captured
  // original. Unknown must not be coerced into a success or auto-retry.
  if(health===false){
    restoreProtectedOriginalFixedRoot();
    deny();
  }
  const evidence=validateFixedActivationEvidence({
    bootstrapPhase:boot.phase,baselineCommit:boot.baselineCommit,
    health,policy
  });
  writeRootPolicy(policy);
  return Object.freeze({
    phase:'bootstrap_activated_needs_two_real_updates',
    baselineCommit:evidence.baselineCommit,
    rootOwned:true,sudoCommands:2,realProtectedUpdates:0,
    safeToReplay:false
  });
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{
    const result=await activateProtectedOSOnce();
    process.stdout.write(JSON.stringify(result)+'\n');
  }catch{
    process.stderr.write('protected_os_activation_denied_or_unknown\n');
    process.exitCode=1;
  }
}
