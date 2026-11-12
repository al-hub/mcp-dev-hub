// #35: root-observed OS isolation of the TWO operational signer keys.
// This does not generate or read private keys, issue approvals, or grant
// installer authority. True Codex/GitHub reviewer provenance is a separate
// live evidence gate. Never infer separation from two different public keys.
import {constants,closeSync,fstatSync,lstatSync,openSync,readFileSync}
  from 'node:fs';

const BASE='/var/lib/mcp-dev-hub-signers';
const TRUST='/etc/mcp-dev-hub/protected-update';
const roles=['reviewer','approval'];
const CODEX_ROOT='/var/lib/mcp-dev-hub-codex-review';
const CODEX_PRIVATE=CODEX_ROOT+'/runner';
const CODEX_FIXED='/usr/local/lib/mcp-dev-hub/protected-codex/code';
const deny=()=>{throw Error('protected_issuer_isolation_denied');};
const UID=/^[1-9][0-9]{0,8}$/;
function dirInfo(path){
  const s=lstatSync(path);
  return {uid:s.uid,gid:s.gid,mode:s.mode&0o777,
    directory:s.isDirectory(),symlink:s.isSymbolicLink()};
}
function fileInfo(path){
  const s=lstatSync(path);
  return {uid:s.uid,gid:s.gid,mode:s.mode&0o777,regular:s.isFile(),
    symlink:s.isSymbolicLink(),links:s.nlink,bytes:s.size};
}
export function pinnedIssuerNumericTrustName(role,kind){
  if(!['worker','codex',...roles].includes(role)||
     (kind!=='uid'&&kind!=='gid'))deny();
  return role+'-'+kind;
}
function readRoleId(role,kind){
  const fd=openSync(TRUST+'/'+pinnedIssuerNumericTrustName(role,kind),
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
function requireLocalCodexKey({codex,workerUid,workerGid,
  reviewerUid=null,reviewerGid=null,approvalUid=null,approvalGid=null,
  codexParents}={}){
 if(!codex||!Number.isSafeInteger(codex.uid)||codex.uid<=0||
    !Number.isSafeInteger(codex.gid)||codex.gid<=0||
    [workerUid,reviewerUid,approvalUid].includes(codex.uid)||
    [workerGid,reviewerGid,approvalGid].includes(codex.gid)||
    !Array.isArray(codexParents)||codexParents.length!==1||
    codexParents.some(p=>p.uid!==0||p.directory!==true||
      p.symlink!==false||(p.mode&0o022)!==0)||
    codex.dir?.directory!==true||codex.dir.symlink!==false||
    codex.dir.uid!==codex.uid||codex.dir.gid!==codex.gid||
    codex.dir.mode!==0o700||codex.key?.regular!==true||
    codex.key.symlink!==false||codex.key.uid!==codex.uid||
    codex.key.gid!==codex.gid||codex.key.mode!==0o400||
    codex.key.links!==1||!Number.isSafeInteger(codex.key.bytes)||
    codex.key.bytes<1||codex.key.bytes>8192)deny();
 return codex.uid;
}
/** Pure, synthetic-testable structural invariant. This NEVER grants root
 * authority: only assertFixedOperationalIssuerIsolation observes OS state.
 */
export function verifyProtectedIssuerIsolationEvidence({
  reviewer,approval,workerUid,workerGid,parentRows,
  localMode=false,codex,codexParents
}={}){
  if(!Number.isSafeInteger(workerUid)||workerUid<=0||
     !Number.isSafeInteger(workerGid)||workerGid<=0||
     !Array.isArray(parentRows)||parentRows.length!==7||
     !parentRows.every(p=>p?.uid===0&&p.directory===true&&
       p.symlink===false&&Number.isSafeInteger(p.mode)&&
       (p.mode&0o022)===0))deny();
  const identities=[reviewer,approval];
  if(!identities.every(r=>r&&Number.isSafeInteger(r.uid)&&r.uid>0&&
       Number.isSafeInteger(r.gid)&&r.gid>0&&r.uid!==workerUid&&
       r.dir?.directory===true&&r.dir?.symlink===false&&
       r.dir.uid===r.uid&&r.dir.mode===0o700&&
       r.key?.regular===true&&r.key?.symlink===false&&
       r.key.uid===r.uid&&r.key.mode===0o400&&
       r.key.links===1&&Number.isSafeInteger(r.key.bytes)&&
       r.key.bytes>0&&r.key.bytes<=8192))deny();
  if(reviewer.uid===approval.uid||
     reviewer.gid===approval.gid||reviewer.gid===workerGid||
     approval.gid===workerGid)deny();
  if(typeof localMode!=='boolean')deny();
  const codexUid=localMode?requireLocalCodexKey({
    codex,workerUid,workerGid,reviewerUid:reviewer.uid,
    reviewerGid:reviewer.gid,approvalUid:approval.uid,
    approvalGid:approval.gid,codexParents
  }):null;
  return Object.freeze({
    state:'os_private_key_metadata_separated',
    ...(localMode?{codexUid}:{}),
    reviewerUid:reviewer.uid,approvalUid:approval.uid,
    workerUid,workerGid,signerProvenanceVerified:false,
    installerAuthorized:false
  });
}
function readSignerMode(){
 const fd=openSync(TRUST+'/signer-mode',
   constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=fstatSync(fd);
  if(!s.isFile()||s.uid!==0||s.nlink!==1||
     (s.mode&0o777)!==0o400||s.size<1||s.size>64)deny();
  const mode=readFileSync(fd,'utf8').trim();
  if(!['wsl-local-v1','external-v1'].includes(mode))deny();
  return mode;
 }finally{closeSync(fd);}
}
function observedCodex(){
 const uid=readRoleId('codex','uid');
 const gid=readRoleId('codex','gid');
 return {uid,gid,dir:dirInfo(CODEX_PRIVATE),
   key:fileInfo(CODEX_PRIVATE+'/private.ed25519.pem')};
}
/** Root-only, read-only C-mode pre-provision guard. The Codex signing
 * identity, fixed executable and private key must ALREADY be independently
 * installed/owner-authenticated before any reviewer accounts are created.
 * It never accesses or returns private key bytes.
 */
export function assertFixedCodexSignerPrerequisites(){
 if(process.getuid?.()!==0||process.geteuid?.()!==0||
    readSignerMode()!=='wsl-local-v1')deny();
 const workerUid=readRoleId('worker','uid');
 const workerGid=readRoleId('worker','gid');
 const codex=observedCodex();
 const parents=[dirInfo(CODEX_ROOT)];
 const pinnedCode=dirInfo(CODEX_FIXED);
 const runner=fileInfo(CODEX_FIXED+'/scripts/protected-update-codex-receipt.mjs');
 if(pinnedCode.uid!==0||pinnedCode.symlink!==false||
    pinnedCode.directory!==true||(pinnedCode.mode&0o022)!==0||
    runner.uid!==0||runner.regular!==true||runner.symlink!==false||
    runner.mode!==0o444||runner.links!==1)deny();
 requireLocalCodexKey({codex,workerUid,workerGid,codexParents:parents});
 return Object.freeze({codexUid:codex.uid,sourceOnly:true,
   installerAuthorized:false});
}
/** Read-only root-side inspection of FIXED paths, never Worker supplied.
 * The installer additionally must verify each public key's actual relation
 * to the private key in its own separate issuer principal and attest to
 * provenance before accepting any signature. Keys are NEVER returned.
 */
export function assertFixedOperationalIssuerIsolation(){
  if(process.geteuid?.()!==0||process.getuid?.()!==0)deny();
  const parents=['/','/var','/var/lib',BASE,
    '/etc','/etc/mcp-dev-hub',TRUST];
  const parentRows=parents.map(dirInfo);
  const workerUid=readRoleId('worker','uid');
  const workerGid=readRoleId('worker','gid');
  const groups=roles.map(role=>{
    const uid=readRoleId(role,'uid');
    const gid=readRoleId(role,'gid');
    const dir=dirInfo(BASE+'/issuer-'+role);
    const key=fileInfo(BASE+'/issuer-'+role+'/private.ed25519.pem');
    return {uid,gid,dir,key};
  });
  const localMode=readSignerMode()==='wsl-local-v1';
  let codex,codexParents;
  if(localMode){
    assertFixedCodexSignerPrerequisites();
    codex=observedCodex();
    codexParents=[dirInfo(CODEX_ROOT)];
  }
  return verifyProtectedIssuerIsolationEvidence({
    reviewer:groups[0],approval:groups[1],
    workerUid,workerGid,parentRows,localMode,codex,codexParents
  });
}
