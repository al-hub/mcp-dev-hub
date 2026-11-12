import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
import {APP_ACCEPTANCE_DOMAIN,APP_ACCEPTANCE_REVIEW_DOMAIN,
 verifySignedAppAcceptance}
 from '../src/ops/protected-update-app-acceptance.mjs';

const head='a'.repeat(40),base='b'.repeat(40),packDigest='c'.repeat(64);
const now=1900000000000;
const approval=generateKeyPairSync('ed25519');
const reviewer=generateKeyPairSync('ed25519');
const unrelated=generateKeyPairSync('ed25519');
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const packet=()=>({
 version:2,repository:'al-hub/mcp-dev-hub',
 scope:'protected-bootstrap-app-approval',
 attestor:'independent-protected-approval',prNumber:39,
 head,base,ciRunId:123,packDigest,
 evidence:{headSha:head,verdict:'passed',gates:{
  root_security:{verdict:'passed'},original_restore:{verdict:'passed'}
 }},
 protectionEvidence:{headSha:head,enforceAdmins:true},
 issuedAtMs:now-1000,expiresAtMs:now+60000
});
function fixture(p=packet(),key=approval){
 const raw=JSON.stringify(p);
 const signatureBase64=sign(null,Buffer.from(APP_ACCEPTANCE_DOMAIN+raw),
  key.privateKey).toString('base64');
 const reviewSignatureBase64=sign(null,Buffer.from(APP_ACCEPTANCE_REVIEW_DOMAIN+raw),
  reviewer.privateKey).toString('base64');
 return {raw,signatureBase64,reviewSignatureBase64,
  pinnedReviewerPublicKeyPem:pem(reviewer),
  pinnedApprovalPublicKeyPem:pem(approval),
  head,base,ciRunId:123,packDigest,nowMs:now};
}
const deny=x=>assert.throws(()=>verifySignedAppAcceptance(x),
 /independent_app_acceptance_denied/);
test('independent approval Ed25519 domain authenticates exact short-lived packet',()=>{
 const f=fixture(),v=verifySignedAppAcceptance(f);
 assert.equal(v.packet.head,head);
 assert.equal(v.packet.packDigest,packDigest);
 assert.match(v.packetSha256,/^[a-f0-9]{64}$/);
 assert.equal(v.expiresAtMs,now+60000);
});
test('JSON, same-owner checksum and absent signature cannot grant App approval',()=>{
 const f=fixture();
 for(const changed of [
  {...f,signatureBase64:undefined},
  {...f,reviewSignatureBase64:undefined},
  {...f,reviewSignatureBase64:f.signatureBase64},
  {...f,pinnedReviewerPublicKeyPem:pem(approval)},
  {...f,pinnedReviewerPublicKeyPem:pem(unrelated)},
  {...f,reviewSignatureBase64:sign(null,
    Buffer.from(APP_ACCEPTANCE_DOMAIN+f.raw),
    reviewer.privateKey).toString('base64')},
  {...f,signatureBase64:'a'.repeat(88)},
  {...f,raw:JSON.stringify({...packet(),evidence:{verdict:'passed'}})},
  {...f,signatureBase64:fixture(packet(),unrelated).signatureBase64},
  {...f,pinnedApprovalPublicKeyPem:pem(unrelated)}
 ])deny(changed);
});
test('valid signature cannot be replayed after HEAD BASE CI or pack moves',()=>{
 const f=fixture();
 for(const changed of [
  {...f,head:'d'.repeat(40)},{...f,base:'e'.repeat(40)},
  {...f,ciRunId:124},{...f,packDigest:'f'.repeat(64)},
  {...f,nowMs:now+60000}
 ])deny(changed);
});
test('wrong scope, role, freshness, extra field and old unsigned v1 fail',()=>{
 const cases=[
  {...packet(),scope:'controller-pair'},
  {...packet(),attestor:'root-owned-checksum'},
  {...packet(),expiresAtMs:now+120001},
  {...packet(),issuedAtMs:now+1},
  {...packet(),extra:true},
  {...packet(),version:1},
  {...packet(),prNumber:17},
  {...packet(),evidence:[]},
  {...packet(),protectionEvidence:null}
 ];
 for(const p of cases)deny(fixture(p));
});
test('noncanonical signed JSON and wrong signing domain fail closed',()=>{
 const p=packet(),f=fixture(p);
 deny({...f,raw:f.raw+'\n'});
 const raw=JSON.stringify(p,null,2);
 const signatureBase64=sign(null,Buffer.from(APP_ACCEPTANCE_DOMAIN+raw),
  approval.privateKey).toString('base64');
 deny({...f,raw,signatureBase64});
 const wrong=sign(null,Buffer.from('mcp-dev-hub/protected-update-approval/v1\\n'+f.raw),
  approval.privateKey).toString('base64');
 deny({...f,signatureBase64:wrong});
});
