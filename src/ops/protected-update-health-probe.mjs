// #35 fixed worker-health observer candidate for protected controller updates.
// No arbitrary command/endpoint, no shell, no Issue/Worker-selected paths.
// This is NOT sufficient proof of full application behavior by itself; only
// authentic live E2E can establish final protected release acceptance.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {inspectProtectedCurrentSnapshot} from './protected-update-release-pointer.mjs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const SERVICES=Object.freeze([
  'mcp-dev-hub-worker-14.service','mcp-dev-hub-dashboard.service'
]);
const UID_RE=/^[1-9][0-9]{0,8}$/;
const deny=()=>{throw Error('protected_health_observer_unknown');};
function run(bin,args,uid,gid,timeout=10000){
  const res=spawnSync(bin,args,{
    uid,gid,cwd:'/',shell:false,timeout,maxBuffer:4096,
    encoding:'utf8',stdio:['ignore','pipe','pipe'],
    env:{
      PATH:'/usr/bin:/bin',LANG:'C',
      HOME:'/',
      XDG_RUNTIME_DIR:'/run/user/'+uid,
      DBUS_SESSION_BUS_ADDRESS:'unix:path=/run/user/'+uid+'/bus'
    }
  });
  if(res.error||res.signal||res.status===null||
     typeof res.stdout!=='string'||res.stdout.length>512)deny();
  return res;
}
/** Pure structural validation of an OS probe's bounded return; test only.
 * The immutable root observer must invoke this itself under a pinned user.
 */
export function evaluateProtectedHealthEvidence({
  services,controllerSyntax,policySyntax
}={}){
  if(!Array.isArray(services)||services.length!==2||
     !services.every((r,i)=>r?.service===SERVICES[i]&&
       r.status===0&&r.output==='active')||
     controllerSyntax?.status!==0||policySyntax?.status!==0)
    return false;
  return true;
}
/** Called only by a privileged, pinned root updater. Returns true/false only
 * for unambiguously observed states. Tool errors/transport/timeouts throw
 * UNKNOWN; never coerce them into healthy or an unsafe automatic rollback.
 */
export function observeProtectedWorkerHealth({
  pinnedWorkerUid,pinnedWorkerGid,expectedCommit,expectedHashes
}={}){
  if(process.geteuid?.()!==0||!UID_RE.test(String(pinnedWorkerUid))||
     !/^[0-9]{1,9}$/.test(String(pinnedWorkerGid))||
     typeof expectedCommit!=='string'||!/^[a-f0-9]{40}$/.test(expectedCommit)||
     !expectedHashes||typeof expectedHashes!=='object')deny();
  const uid=Number(pinnedWorkerUid),gid=Number(pinnedWorkerGid);
  if(!Number.isSafeInteger(uid)||!Number.isSafeInteger(gid))deny();
  const snap=inspectProtectedCurrentSnapshot(ROOT);
  if(snap.commit!==expectedCommit||snap.files.length!==2||
     !snap.files.every(f=>f.sha256===expectedHashes[f.name]))deny();
  const serviceResult=run('/usr/bin/systemctl',
    ['--user','is-active',...SERVICES],uid,gid);
  const lines=serviceResult.stdout.trim().split(/\r?\n/);
  if(lines.length!==2||lines.some(s=>!['active','inactive','failed',
    'activating','deactivating','unknown'].includes(s)))deny();
  // Some inactive units return exit 3. This is a confirmed unhealthy state,
  // never a reason to bypass the signed update or invent a synthetic PASS.
  if(serviceResult.status!==0&&serviceResult.status!==3)deny();
  const names=['ai-github-canary.mjs','ai-github-canary-policy.mjs'];
  const results=names.map(name=>{
    const path=ROOT+'/current/'+name;
    const check=run('/usr/bin/node',['--check',path],uid,gid,15000);
    if(check.status!==0&&check.status!==1)deny();
    return {status:check.status};
  });
  return evaluateProtectedHealthEvidence({
    services:SERVICES.map((service,i)=>({
      service,status:lines[i]==='active'?0:3,output:lines[i]
    })),
    controllerSyntax:results[0],policySyntax:results[1]
  });
}
export const PROTECTED_HEALTH_UNIT_NAMES=SERVICES;
