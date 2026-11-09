// #35 source-only root-owned routine signer attempt fence.
// Never infer replay permission from process exit or missing journal.
import {constants,closeSync,fstatSync,fsyncSync,lstatSync,openSync,
  readFileSync,writeSync,unlinkSync,fchmodSync} from 'node:fs';
const OPS='/var/lib/mcp-dev-hub-signers/routine-operations';
const LOCK=OPS+'/.active-routine';
const ID=/^[a-f0-9]{32}$/;
const deny=()=>{throw Error('routine_dispatch_unknown_or_denied');};
function root(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0)deny();
 for(const p of ['/','/var','/var/lib',
  '/var/lib/mcp-dev-hub-signers',OPS]){
  const s=lstatSync(p);
  if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==0||
   (s.mode&0o022)!==0||
   (p===OPS&&(s.mode&0o777)!==0o755))deny();
 }
}
function directorySync(){
 const fd=openSync(OPS,constants.O_RDONLY|constants.O_NOFOLLOW|
  constants.O_DIRECTORY);
 try{fsyncSync(fd);}finally{closeSync(fd);}
}
export function parseRoutineDispatchFence(raw){
 let a;try{a=JSON.parse(raw);}catch{deny();}
 if(!a||Array.isArray(a)||typeof a!=='object'||
  Object.keys(a).sort().join(',')!=='operationId,state,version'||
  JSON.stringify(a)!==raw||a.version!==1||
  !ID.test(a.operationId||'')||a.state!=='dispatched_or_unknown')deny();
 return Object.freeze(a);
}
function readFence(){
 const fd=openSync(LOCK,constants.O_RDONLY|constants.O_NOFOLLOW|
  constants.O_NONBLOCK);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
   (s.mode&0o777)!==0o600||s.size<1||s.size>256)deny();
  return parseRoutineDispatchFence(readFileSync(fd,'utf8'));
 }finally{closeSync(fd);}
}
/** Root-only readback: an existing active fence is never a retry grant.
 * The returned state does not disclose another operation's identifier.
 */
export function inspectRoutineDispatchFence(operationId){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    !ID.test(operationId||''))deny();
 try{root();}catch(e){
  if(e.code==='ENOENT')return Object.freeze({
   state:'not_provisioned',safeToReplay:false});
  throw e;
 }
 let s;try{s=lstatSync(LOCK);}catch(e){
  if(e.code==='ENOENT')return Object.freeze({
   state:'inactive',safeToReplay:false});
  throw e;
 }
 if(!s.isFile()||s.isSymbolicLink())deny();
 const actual=readFence();
 return Object.freeze({
  state:actual.operationId===operationId
    ?'active_same_operation_unknown':'other_operation_active_unknown',
  safeToReplay:false
 });
}
export function acquireRoutineDispatchFence(operationId){
 root();
 if(!ID.test(operationId||''))deny();
 const b=Buffer.from(JSON.stringify({
  version:1,operationId,state:'dispatched_or_unknown'
 }));
 const fd=openSync(LOCK,constants.O_WRONLY|constants.O_CREAT|
  constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{
  if(writeSync(fd,b,0,b.length,0)!==b.length)deny();
  fchmodSync(fd,0o600);fsyncSync(fd);
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
   s.size!==b.length||(s.mode&0o777)!==0o600)deny();
 }finally{closeSync(fd);}
 directorySync();
 return Object.freeze({operationId,safeToReplay:false});
}
export function requireNoRoutineDispatchFence(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0)deny();
 try{root();}catch(e){
  if(e.code==='ENOENT')return true;
  throw e;
 }
 try{lstatSync(LOCK);}catch(e){
  if(e.code==='ENOENT')return true;
  throw e;
 }
 readFence();deny();
}
export function releaseTerminalRoutineDispatchFence(operationId,phase){
 root();
 if(!ID.test(operationId||'')||
  !['verified','rolled_back'].includes(phase)||
  readFence().operationId!==operationId)deny();
 unlinkSync(LOCK);directorySync();
 return Object.freeze({operationId,phase,safeToReplay:false});
}
