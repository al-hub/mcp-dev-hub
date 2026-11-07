// #35: root-observed OS isolation of the TWO operational signer keys.
// This does not generate or read private keys, issue approvals, or grant
// installer authority. True Codex/GitHub reviewer provenance is a separate
// live evidence gate. Never infer separation from two different public keys.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';

const BASE='/var/lib/mcp-dev-hub';
const TRUST='/etc/mcp-dev-hub/protected-update';
const roles=['reviewer','approval'];
const deny=()=>{throw Error('protected_issuer_isolation_denied');};
const UID=/^[1-9][0-9]{0,8}$/;
function dirInfo(path){
  const s=lstatSync(path);
  return {uid:s.uid,mode:s.mode&0o777,
    directory:s.isDirectory(),symlink:s.isSymbolicLink()};
}
function fileInfo(path){
  const s=lstatSync(path);
  return {uid:s.uid,mode:s.mode&0o777,regular:s.isFile(),
    symlink:s.isSymbolicLink(),links:s.nlink,bytes:s.size};
}
function readRoleUid(role){
  const fd=openSync(TRUST+'/'+role+'-uid',
    constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const s=fstatSync(fd);
    if(!s.isFile()||s.uid!==0||s.nlink!==1||
       (s.mode&0o777)!==0o400||s.size<1||s.size>16)deny();
    const value=readFileSync(fd,'utf8').trim();
    if(!UID.test(value))deny();
    return Number(value);
  }finally{closeSync(fd);}
}
/** Pure, synthetic-testable structural invariant. This NEVER grants root
 * authority: only assertFixedOperationalIssuerIsolation observes OS state.
 */
export function verifyProtectedIssuerIsolationEvidence({
  reviewer,approval,workerUid,parentRows
}={}){
  if(!Number.isSafeInteger(workerUid)||workerUid<=0||
     !Array.isArray(parentRows)||parentRows.length!==5||
     !parentRows.every(p=>p?.uid===0&&p.directory===true&&
       p.symlink===false&&Number.isSafeInteger(p.mode)&&
       (p.mode&0o022)===0))deny();
  const identities=[reviewer,approval];
  if(!identities.every(r=>r&&Number.isSafeInteger(r.uid)&&r.uid>0&&
       Number.isSafeInteger(r.gid)&&r.gid>=0&&r.uid!==workerUid&&
       r.dir?.directory===true&&r.dir?.symlink===false&&
       r.dir.uid===r.uid&&r.dir.mode===0o700&&
       r.key?.regular===true&&r.key?.symlink===false&&
       r.key.uid===r.uid&&r.key.mode===0o400&&
       r.key.links===1&&Number.isSafeInteger(r.key.bytes)&&
       r.key.bytes>0&&r.key.bytes<=8192))deny();
  if(reviewer.uid===approval.uid||
     reviewer.gid===approval.gid)deny();
  return Object.freeze({
    state:'os_private_key_metadata_separated',
    reviewerUid:reviewer.uid,approvalUid:approval.uid,
    workerUid,signerProvenanceVerified:false,installerAuthorized:false
  });
}
/** Read-only root-side inspection of FIXED paths, never Worker supplied.
 * The installer additionally must verify each public key's actual relation
 * to the private key in its own separate issuer principal and attest to
 * provenance before accepting any signature. Keys are NEVER returned.
 */
export function assertFixedOperationalIssuerIsolation(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0)deny();
  const parents=['/','/var','/var/lib',BASE,TRUST];
  const parentRows=parents.map(dirInfo);
  const workerUid=readRoleUid('worker');
  const groups=roles.map(role=>{
    const uid=readRoleUid(role);
    const gid=readRoleUid(role+'-gid');
    const dir=dirInfo(BASE+'/issuer-'+role);
    const key=fileInfo(BASE+'/issuer-'+role+'/private.ed25519.pem');
    return {uid,gid,dir,key};
  });
  return verifyProtectedIssuerIsolationEvidence({
    reviewer:groups[0],approval:groups[1],
    workerUid,parentRows
  });
}
