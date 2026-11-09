// #35 source-only verifier for independently signed PC/Galaxy/private-SSE
// and original-root/recovery acceptance proofs. No private keys or sign API.
// This binds signed external TEST ATTESTATIONS to a source/HEAD; it cannot
// itself measure a device, certify a test, or authorize App/root operations.
// Trust anchors must be independently provisioned by an authorized owner.
import {createHash,createPublicKey,verify} from 'node:crypto';

export const DEVICE_GATE_DOMAIN='mcp-dev-hub/independent-device-gate/v1\n';
export const ROOT_GATE_DOMAIN='mcp-dev-hub/independent-root-gate/v1\n';
const DEVICE=['private_sse','pc','galaxy'];
const ROOT=['root_security','original_restore'];
export const EXTERNAL_APP_GATES=Object.freeze([...DEVICE,...ROOT]);
const CLAIM_FIELDS=['version','repository','scope','source','gate','head',
 'base','ciRunId','packDigest','verdict','evidenceId','proofDigest',
 'issuedAtMs','expiresAtMs'];
const KEYS=['gate','claimJson','signatureBase64'];
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const EVIDENCE=/^verified-[a-z0-9-]{6,100}$/;
const B64=/^[A-Za-z0-9+/]{86}==$/;
const deny=()=>{throw Error('independent_external_app_gate_denied');};
const exact=(o,fields)=>o!==null&&typeof o==='object'&&
 !Array.isArray(o)&&Object.keys(o).length===fields.length&&
 fields.every(f=>Object.hasOwn(o,f));
function key(pem){
 let k;try{k=createPublicKey(pem);}catch{deny();}
 if(k.asymmetricKeyType!=='ed25519')deny();
 return k;
}
const der=k=>k.export({type:'spki',format:'der'});
function canonical(raw,fields,max){
 if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')<1||
    Buffer.byteLength(raw,'utf8')>max)deny();
 let o;try{o=JSON.parse(raw);}catch{deny();}
 if(!exact(o,fields)||JSON.stringify(o)!==raw)deny();
 return o;
}
/** The packet contains exactly five *externally* signed receipt references.
 * CI and security still come from a separately verified live GitHub run.
 * Distinct external device/root keys cannot be the in-process Codex/reviewer
 * or approval signer, preventing a role from self-attesting its own gates.
 */
export function verifyExternalAppGateReceipts({
 raw,devicePublicKeyPem,rootPublicKeyPem,reviewerPublicKeyPem,
 approvalPublicKeyPem,codexPublicKeyPem,head,base,ciRunId,packDigest,
 nowMs
}={}){
 if(!SHA.test(head||'')||!SHA.test(base||'')||base===head||
    !HASH.test(packDigest||'')||
    !Number.isSafeInteger(ciRunId)||ciRunId<1||
    !Number.isSafeInteger(nowMs)||nowMs<1)deny();
 const kDevice=key(devicePublicKeyPem),kRoot=key(rootPublicKeyPem);
 const keys=[kDevice,kRoot,key(reviewerPublicKeyPem),
  key(approvalPublicKeyPem),key(codexPublicKeyPem)];
 for(let i=0;i<keys.length;i++)
  for(let j=i+1;j<keys.length;j++)
   if(der(keys[i]).equals(der(keys[j])))deny();
 const packet=canonical(raw,['version','repository','scope',
  'receipts'],12000);
 if(packet.version!==1||packet.repository!=='al-hub/mcp-dev-hub'||
    packet.scope!=='protected-bootstrap-app-gates'||
    !Array.isArray(packet.receipts)||
    packet.receipts.length!==EXTERNAL_APP_GATES.length)deny();
 const ids=new Set(),proofs=new Set(),result={};
 for(let i=0;i<packet.receipts.length;i++){
  const row=packet.receipts[i],gate=EXTERNAL_APP_GATES[i];
  if(!exact(row,KEYS)||row.gate!==gate||
     typeof row.signatureBase64!=='string'||
     !B64.test(row.signatureBase64))deny();
  const claim=canonical(row.claimJson,CLAIM_FIELDS,1800);
  const source=DEVICE.includes(gate)?'independent-device':
    'independent-root';
  const pub=source==='independent-device'?kDevice:kRoot;
  const domain=source==='independent-device'?
   DEVICE_GATE_DOMAIN:ROOT_GATE_DOMAIN;
  if(claim.version!==1||
     claim.repository!=='al-hub/mcp-dev-hub'||
     claim.scope!=='protected-bootstrap-app-gate'||
     claim.source!==source||claim.gate!==gate||
     claim.head!==head||claim.base!==base||
     claim.ciRunId!==ciRunId||
     claim.packDigest!==packDigest||claim.verdict!=='passed'||
     !EVIDENCE.test(claim.evidenceId||'')||
     !HASH.test(claim.proofDigest||'')||
     ids.has(claim.evidenceId)||proofs.has(claim.proofDigest)||
     !Number.isSafeInteger(claim.issuedAtMs)||
     !Number.isSafeInteger(claim.expiresAtMs)||
     claim.issuedAtMs<=0||claim.issuedAtMs>nowMs||
     claim.expiresAtMs<=nowMs||
     claim.expiresAtMs-claim.issuedAtMs>1800000)deny();
  const bytes=Buffer.from(row.signatureBase64,'base64');
  if(bytes.length!==64||bytes.toString('base64')!==row.signatureBase64||
     !verify(null,Buffer.from(domain+row.claimJson),pub,bytes))deny();
  ids.add(claim.evidenceId);proofs.add(claim.proofDigest);
  result[gate]=Object.freeze({
   headSha:head,verdict:'passed',evidenceId:claim.evidenceId
  });
 }
 return Object.freeze({
  gates:Object.freeze(result),
  evidenceBundleSha256:createHash('sha256').update(raw).digest('hex'),
  validUntilMs:Math.min(...packet.receipts.map(
   r=>JSON.parse(r.claimJson).expiresAtMs)),
  independentProducerInstalled:false,physicalEvidenceAudited:false
 });
}
