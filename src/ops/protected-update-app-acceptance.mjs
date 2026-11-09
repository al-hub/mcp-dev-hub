// #35 uninstalled, fixed two-principal App acceptance gate.
// Canonical packet + domain-separated reviewer/approval Ed25519 signatures
// bind facts; they do NOT prove real-world evidence without separately
// operated, immutable, audited issuer roles and independently checked gates.
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
const der=k=>k.export({type:'spki',format:'der'});
function canonical(raw,head,base,ciRunId,packDigest,nowMs){
 if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>12000||
    !SHA.test(head||'')||!SHA.test(base||'')||head===base||
    !HASH.test(packDigest||'')||
    !Number.isSafeInteger(ciRunId)||ciRunId<=0||
    !Number.isSafeInteger(nowMs)||nowMs<=0)deny();
 let p;try{p=JSON.parse(raw);}catch{deny();}
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
 return Object.freeze(p);
}
function keyOf(pem){
 let k;try{k=createPublicKey(pem);}catch{deny();}
 if(k.asymmetricKeyType!=='ed25519')deny();
 return k;
}
function signed(raw,signatureBase64,domain,pub){
 if(typeof signatureBase64!=='string'||!SIG.test(signatureBase64))deny();
 const sig=Buffer.from(signatureBase64,'base64');
 if(sig.length!==64||sig.toString('base64')!==signatureBase64||
    !verify(null,Buffer.from(domain+raw),pub,sig))deny();
}
/** Independent reviewer must have first audited the genuine packet evidence.
 * This function only checks the cryptographic handoff to the distinct approval
 * principal; it cannot certify physical gate provenance on its own.
 */
export function verifyAppAcceptanceReviewer({
 raw,reviewSignatureBase64,pinnedReviewerPublicKeyPem,
 head,base,ciRunId,packDigest,nowMs
}={}){
 const p=canonical(raw,head,base,ciRunId,packDigest,nowMs);
 signed(raw,reviewSignatureBase64,APP_ACCEPTANCE_REVIEW_DOMAIN,
    keyOf(pinnedReviewerPublicKeyPem));
 return Object.freeze({packet:p,
  packetSha256:createHash('sha256').update(raw).digest('hex')});
}
export function verifySignedAppAcceptance({
 raw,signatureBase64,pinnedApprovalPublicKeyPem,
 reviewSignatureBase64,pinnedReviewerPublicKeyPem,
 head,base,ciRunId,packDigest,nowMs
}={}){
 const reviewer=verifyAppAcceptanceReviewer({
  raw,reviewSignatureBase64,pinnedReviewerPublicKeyPem,
  head,base,ciRunId,packDigest,nowMs
 });
 const key=keyOf(pinnedApprovalPublicKeyPem);
 if(der(key).equals(der(keyOf(pinnedReviewerPublicKeyPem))))deny();
 signed(raw,signatureBase64,APP_ACCEPTANCE_DOMAIN,key);
 return Object.freeze({
  packet:reviewer.packet,packetSha256:reviewer.packetSha256,
  expiresAtMs:reviewer.packet.expiresAtMs
 });
}
