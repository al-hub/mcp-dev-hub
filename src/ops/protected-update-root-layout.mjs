// #35: fixed OS ancestry guard for an eventual immutable root updater.
// Candidate code ONLY, not an administrator entrypoint or install grant.
// Never use a caller's directory list or owner as authorization evidence.
import {lstatSync} from 'node:fs';

const ROOT='/usr/local/lib/mcp-dev-hub';
const STATE='/var/lib/mcp-dev-hub/protected-update';
const DIRS=Object.freeze([
  '/','/usr','/usr/local','/usr/local/lib',ROOT,ROOT+'/versions',
  '/var','/var/lib','/var/lib/mcp-dev-hub',STATE
]);
const deny=()=>{throw Error('protected_root_layout_denied');};

/** PURE fixture shape check, NOT OS authorization. The caller supplies all
 * evidence: do not treat a PASS here as filesystem ownership proof.
 * Production must exclusively call assertFixedRootProtectedUpdateLayout().
 */
export function verifyProtectedLayoutEvidence(rows){
  if(!Array.isArray(rows)||rows.length!==DIRS.length)deny();
  for(let i=0;i<DIRS.length;i++){
    const r=rows[i];
    if(!r||typeof r!=='object'||Object.keys(r).sort().join(',')!==
       'directory,mode,path,symlink,uid'||
       r.path!==DIRS[i]||r.directory!==true||r.symlink!==false||
       r.uid!==0||!Number.isSafeInteger(r.mode)||
       (r.mode&0o022)!==0||
       (r.mode&0o500)!==0o500)deny();
    if(r.path===STATE&&(r.mode&0o077)!==0)deny();
  }
  return true;
}

/** Privileged immutable supervisor only: verify real lstat of every fixed
 * ancestor of release and journal roots, before ANY read/write effect.
 * This does NOT validate updater source-code integrity, review issuance,
 * current pointers, state data or credentials: those are distinct gates.
 */
export function assertFixedRootProtectedUpdateLayout(){
  if(typeof process.geteuid!=='function'||process.geteuid()!==0)deny();
  const rows=DIRS.map(path=>{
    const st=lstatSync(path);
    return {
      path,uid:st.uid,mode:st.mode&0o777,
      directory:st.isDirectory(),symlink:st.isSymbolicLink()
    };
  });
  verifyProtectedLayoutEvidence(rows);
  // Never return a mockable proof to be passed on as root authority.
  return true;
}
