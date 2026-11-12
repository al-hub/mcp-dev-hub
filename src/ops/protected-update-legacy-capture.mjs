// #35: read-only capture of the existing root-protected controller pair.
// NOT a privileged updater, installer, backup, or authority to run code as root.
// An immutable root supervisor must independently validate ALL ancestors,
// bind the fixed legacy root, persist a verified backup, and revalidate bytes
// before switching the first protected version. Never run checkout code as root.
import {createHash} from 'node:crypto';
import {
  constants,closeSync,fstatSync,lstatSync,openSync,readFileSync,realpathSync
} from 'node:fs';
import {isAbsolute,join,resolve} from 'node:path';
import {RELEASE_FILES} from './protected-update-release-pointer.mjs';

const MAX_BYTES=256*1024;
const deny=()=>{throw Error('protected_legacy_capture_denied');};
const FLAGS=constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

function sameInode(a,b){
  return a.dev===b.dev&&a.ino===b.ino&&a.uid===b.uid;
}
function checkedRoot(root,owner){
  if(typeof root!=='string'||!isAbsolute(root)||resolve(root)!==root)
    deny();
  const st=lstatSync(root);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==owner||
     (st.mode&0o022)!==0||realpathSync(root)!==root)deny();
  return st;
}
function captureOne(root,name,owner){
  if(!RELEASE_FILES.includes(name))deny();
  const path=join(root,name);
  const before=lstatSync(path);
  if(!before.isFile()||before.isSymbolicLink()||
     before.nlink!==1||before.uid!==owner||
     (before.mode&0o777)!==0o555||
     before.size<1||before.size>MAX_BYTES)deny();
  const fd=openSync(path,FLAGS);
  try{
    const opened=fstatSync(fd);
    if(!opened.isFile()||!sameInode(before,opened)||
       opened.nlink!==1||(opened.mode&0o777)!==0o555||
       opened.size!==before.size)deny();
    const bytes=readFileSync(fd);
    const afterFd=fstatSync(fd);
    const afterPath=lstatSync(path);
    if(bytes.length!==before.size||
       !sameInode(before,afterFd)||!sameInode(before,afterPath)||
       !afterPath.isFile()||afterPath.isSymbolicLink()||
       afterFd.size!==before.size||afterPath.size!==before.size||
       afterFd.mtimeMs!==before.mtimeMs||
       afterPath.mtimeMs!==before.mtimeMs)deny();
    return {name,bytes,sha256:digest(bytes)};
  }finally{closeSync(fd);}
}

/** Capture only the two existing flat-format protected files by name.
 * This cannot install, move, chmod, restart or execute anything.
 * Returned Buffers are mutable by JavaScript; a separately installed trusted
 * supervisor MUST hash-check them again when persisting the original backup.
 * The caller cannot set a trusted owner: it is the actual process euid.
 */
export function captureLegacyProtectedPair(root){
  if(typeof process.geteuid!=='function')deny();
  const owner=process.geteuid();
  const rootBefore=checkedRoot(root,owner);
  const captured=RELEASE_FILES.map(name=>captureOne(root,name,owner));
  const rootAfter=checkedRoot(root,owner);
  if(!sameInode(rootBefore,rootAfter))deny();
  const contents=Object.freeze(Object.fromEntries(
    captured.map(({name,bytes})=>[name,bytes])
  ));
  const files=Object.freeze(captured.map(({name,bytes,sha256})=>
    Object.freeze({name,bytes:bytes.length,sha256})
  ));
  return Object.freeze({files,contents});
}
