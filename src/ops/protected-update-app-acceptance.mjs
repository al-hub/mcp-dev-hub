// #35 fixed signed App-acceptance gate: source-only, never installation authority.
// A root-owned JSON file or a checksum from its directory is NOT independent
// approval. Only a canonical, fresh Ed25519 claim from the separately pinned
// approval principal may endorse the evidence used by the fixed App publisher.
import {createHash,createPublicKey,verify} from 'node:crypto';

export const APP_ACCEPTANCE_DOMAIN='mcp-dev-hub/app-acceptance/v1\n';
export const APP_ACCEPTANCE_REVIEW_DOMAIN=
 'mcp-dev-hub/app-acceptance-independent-review/v1\n';
const KEYS=['version','repository','scope','attestor','prNumber','head','base',
 'ciRunId','packDigest','evidence','protectionEvidence','issuedAtMs','expiresAtMs'];
const SHA=/^[a-f0-9]{40}$/,HASH=/^[a-f0-9]{64}$/;
const SIG=/^[A-Za-z0-9+/]{86}==$/;
const deny=()=>{throw Error('independent_app_acceptance_denied');};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export function verifySignedAppAcceptance({
 raw,signatureBase64,pinnedApprovalPublicKeyPem,
 reviewSignatureBase64,pinnedReviewerPublicKeyPem,
 head,base,ciRunId,packDigest,nowMs
}={}){
 if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>12000||
    typeof signatureBase64!=='string'||!SIG.test(signatureBase64)||
    typeof reviewSignatureBase64!=='string'||!SIG.test(reviewSignatureBase64)||
    typeof pinnedApprovalPublicKeyPem!=='string'||
    typeof pinnedReviewerPublicKeyPem!=='string'||
    !SHA.test(head||'')||!SHA.test(base||'')||head===base||
    !HASH.test(packDigest||'')||
    !Number.isSafeInteger(ciRunId)||ciRunId<=0||
    !Number.isSafeInteger(nowMs)||nowMs<=0)deny();
 let p;
 try{p=JSON.parse(raw);}catch{deny();}
 if(!object(p)||Object.keys(p).length!==KEYS.length||
    !KEYS.every(k=>Object.hasOwn(p,k))||JSON.stringify(p)!==raw||
    p.version!==2||p.repository!=='al-hub/mcp-dev-hub'||
    p.scope!=='protected-bootstrap-app-approval'||
    p.attestor!=='independent-protected-approval'||
    p.prNumber!==39||p.head!==head||p.base!==base||
    p.ciRunId!==ciRunId||p.packDigest!==packDigest||
    !object(p.evidence)||!object(p.protectionEvidence)||
    !Number.isSafeInteger(p.issuedAtMs)||p.issuedAtMs<=0||
    !Number.isSafeInteger(p.expiresAtMs)||
    p.issuedAtMs>nowMs||p.expiresAtMs<=nowMs||
    p.expiresAtMs-p.issuedAtMs>120000)deny();
 try{
  const key=createPublicKey(pinnedApprovalPublicKeyPem);
  const reviewer=createPublicKey(pinnedReviewerPublicKeyPem);
  if(key.asymmetricKeyType!=='ed25519'||
     reviewer.asymmetricKeyType!=='ed25519'||
     key.export({type:'spki',format:'der'}).equals(
      reviewer.export({type:'spki',format:'der'})))deny();
  for(const [signature,domain,pub] of [
   [signatureBase64,APP_ACCEPTANCE_DOMAIN,key],
   [reviewSignatureBase64,APP_ACCEPTANCE_REVIEW_DOMAIN,reviewer]
  ]){
   const sig=Buffer.from(signature,'base64');
   if(sig.length!==64||sig.toString('base64')!==signature||
      !verify(null,Buffer.from(domain+raw),pub,sig))deny();
  }
 }catch{deny();}
 return Object.freeze({
  packet:Object.freeze(p),
  packetSha256:createHash('sha256').update(raw).digest('hex'),
  expiresAtMs:p.expiresAtMs
 });
}
