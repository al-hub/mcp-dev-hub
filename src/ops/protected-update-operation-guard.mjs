// #35 source-only, fail-closed serialization for updater vs original restore.
// No caller can gain root privileges from this module. Only immutable,
// independently reviewed fixed root entrypoints may invoke it in production.
import {createHash} from 'node:crypto';
import {
  chmodSync,closeSync,constants,fchmodSync,fstatSync,fsyncSync,
  lstatSync,openSync,readFileSync,unlinkSync,writeSync
} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';

const LOCK='.protected-operation.lock';
const FENCE='.protected-original-restored';
const HASH=/^[a-f0-9]{64}$/;
const deny=()=>{throw Error('protected_operation_guard_denied_or_unknown');};
const flags=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
function checkedRoot(root){
  if(typeof root!=='string'||!isAbsolute(root)||resolve(root)!==root||
     typeof process.geteuid!=='function')deny();
  const st=lstatSync(root);
  if(!st.isDirectory()||st.isSymbolicLink()||
     st.uid!==process.geteuid()||(st.mode&0o022)!==0)deny();
  return st.uid;
}
function hasPath(path){
  try{lstatSync(path);return true;}
  catch(e){if(e.code==='ENOENT')return false;throw e;}
}
function syncRoot(root){
  const fd=openSync(root,constants.O_RDONLY|constants.O_NOFOLLOW|
    constants.O_DIRECTORY);
  try{if(!fstatSync(fd).isDirectory())deny();fsyncSync(fd);}
  finally{closeSync(fd);}
}
/** The actual launched flat controller must remain the root-pinned wrapper,
 * not merely a healthy file under versions/current. Expected bytes come
 * exclusively from the authenticated immutable bootstrap package.
 */
export function assertPinnedProtectedLauncher(root,expectedSha256){
  const owner=checkedRoot(root);
  if(typeof expectedSha256!=='string'||!HASH.test(expectedSha256)||
     hasPath(join(root,FENCE)))deny();
  const fd=openSync(join(root,'ai-github-canary.mjs'),flags);
  try{
    const before=fstatSync(fd);
    if(!before.isFile()||before.uid!==owner||before.nlink!==1||
       (before.mode&0o777)!==0o555||before.size<1||
       before.size>256*1024)deny();
    const bytes=readFileSync(fd);
    const after=fstatSync(fd);
    if(bytes.length!==before.size||after.dev!==before.dev||
       after.ino!==before.ino||after.size!==before.size||
       after.mtimeMs!==before.mtimeMs||
       createHash('sha256').update(bytes).digest('hex')!==expectedSha256)
      deny();
  }finally{closeSync(fd);}
  return true;
}
/** Exclusive crash-durable operation guard. A crash or UNKNOWN exception
 * intentionally leaves the lock; no automatic stale-lock theft/replay.
 * The lock spans ALL root-side verification, switch and health/rollback.
 */
export async function withProtectedOperationGuard(root,work){
  const owner=checkedRoot(root);
  if(typeof work!=='function'||hasPath(join(root,FENCE)))deny();
  const lock=join(root,LOCK);
  const fd=openSync(lock,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{
    fchmodSync(fd,0o600);
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==owner||st.nlink!==1||
       (st.mode&0o777)!==0o600)deny();
    fsyncSync(fd);syncRoot(root);
    if(hasPath(join(root,FENCE)))deny();
    const result=await work();
    if(result===undefined)deny();
    unlinkSync(lock);syncRoot(root);
    return result;
  }finally{closeSync(fd);}
}
/** Called only AFTER the exclusive guard is held, BEFORE any original
 * controller replacement. The permanent fence survives lock release and
 * power loss; reactivation requires a separate explicitly approved repair.
 */
export function markProtectedOriginalRecovery(root){
  const owner=checkedRoot(root);
  const held=lstatSync(join(root,LOCK));
  if(!held.isFile()||held.isSymbolicLink()||held.uid!==owner||
     (held.mode&0o777)!==0o600||held.nlink!==1)deny();
  const fd=openSync(join(root,FENCE),constants.O_WRONLY|
    constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o400);
  try{
    fchmodSync(fd,0o400);
    const bytes=Buffer.from('original_restore_pending_or_completed\\n');
    if(writeSync(fd,bytes,0,bytes.length,0)!==bytes.length)deny();
    const st=fstatSync(fd);
    if(!st.isFile()||st.uid!==owner||st.nlink!==1||
       (st.mode&0o777)!==0o400||st.size!==bytes.length)deny();
    fsyncSync(fd);
  }finally{closeSync(fd);}
  syncRoot(root);
  return Object.freeze({state:'original_recovery_fenced_no_updates'});
}
