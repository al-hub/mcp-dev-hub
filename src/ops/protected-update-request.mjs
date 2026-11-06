// #35: untrusted worker request is DATA ONLY; never a command or permission.
// Root updater code, trust anchors, repository, paths and service policy are
// fixed by a separately approved immutable OS administrator bootstrap.
const REPO='al-hub/mcp-dev-hub';
const SHA=/^[a-f0-9]{40}$/;
const ID=/^[a-f0-9]{32}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const KEYS=Object.freeze([
  'version','repository','prNumber','head','base','ciRunId','operationId',
  'manifestJson','approvalJson','approvalSignatureBase64',
  'reviewJson','reviewSignatureBase64'
]);
const fail=()=>{throw Error('protected_update_request_denied');};
const bounded=(s,n)=>typeof s==='string'&&
  Buffer.byteLength(s,'utf8')>=1&&Buffer.byteLength(s,'utf8')<=n;
export function parseProtectedUpdateRequest(raw){
  if(!bounded(raw,12500))fail();
  let v;
  try{v=JSON.parse(raw);}catch{fail();}
  if(!v||typeof v!=='object'||Array.isArray(v)||
     Object.keys(v).length!==KEYS.length||
     !KEYS.every(k=>Object.hasOwn(v,k))||
     JSON.stringify(v)!==raw||v.version!==1||v.repository!==REPO||
     !Number.isSafeInteger(v.prNumber)||v.prNumber<1||
     !Number.isSafeInteger(v.ciRunId)||v.ciRunId<1||
     typeof v.head!=='string'||!SHA.test(v.head)||
     typeof v.base!=='string'||!SHA.test(v.base)||v.head===v.base||
     typeof v.operationId!=='string'||!ID.test(v.operationId)||
     !bounded(v.manifestJson,4096)||!bounded(v.approvalJson,2048)||
     !bounded(v.reviewJson,2048)||
     typeof v.approvalSignatureBase64!=='string'||
     !B64.test(v.approvalSignatureBase64)||
     typeof v.reviewSignatureBase64!=='string'||
     !B64.test(v.reviewSignatureBase64))fail();
  // The caller may not choose installer path, command, signer, key, PID,
  // credential, permissions, root policy, restart or recovery behavior.
  return Object.freeze({
    prNumber:v.prNumber,head:v.head,base:v.base,ciRunId:v.ciRunId,
    operationId:v.operationId,manifestJson:v.manifestJson,
    approvalJson:v.approvalJson,
    signatureBase64:v.approvalSignatureBase64,
    reviewJson:v.reviewJson,
    reviewSignatureBase64:v.reviewSignatureBase64
  });
}
