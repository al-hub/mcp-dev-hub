import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {DEVICE_GATE_DOMAIN,ROOT_GATE_DOMAIN,EXTERNAL_APP_GATES,
 verifyExternalAppGateReceipts}
 from '../src/ops/protected-update-app-gate-provenance.mjs';
const nowMs=1900000000000;
const head='a'.repeat(40),base='b'.repeat(40),packDigest='c'.repeat(64);
const make=()=>generateKeyPairSync('ed25519');
const device=make(),root=make(),reviewer=make(),approval=make(),
 codex=make(),outsider=make();
const pem=k=>k.publicKey.export({type:'spki',format:'pem'});
const signClaim=(key,domain,raw)=>sign(null,Buffer.from(domain+raw),
 key.privateKey).toString('base64');
const sha=s=>createHash('sha256').update(s).digest('hex');
const FIXED=EXTERNAL_APP_GATES;
function receipt(gate,i){
 const deviceGate=i<3,k=deviceGate?device:root;
 const source=deviceGate?'independent-device':'independent-root';
 const domain=deviceGate?DEVICE_GATE_DOMAIN:ROOT_GATE_DOMAIN;
 const claimJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',
  scope:'protected-bootstrap-app-gate',source,gate,
  head,base,ciRunId:12345,packDigest,verdict:'passed',
  evidenceId:'verified-'+gate.replaceAll('_','-')+'-proof',
  proofDigest:sha('synthetic-private-gate-'+gate),
  issuedAtMs:nowMs-1000,expiresAtMs:nowMs+120000
 });
 return {gate,claimJson,signatureBase64:signClaim(k,domain,claimJson)};
}
const bundle=()=>({version:1,repository:'al-hub/mcp-dev-hub',
 scope:'protected-bootstrap-app-gates',
 receipts:FIXED.map(receipt)});
function args(packet=bundle()){
 return {raw:JSON.stringify(packet),
  devicePublicKeyPem:pem(device),rootPublicKeyPem:pem(root),
  reviewerPublicKeyPem:pem(reviewer),
  approvalPublicKeyPem:pem(approval),
  codexPublicKeyPem:pem(codex),
  head,base,ciRunId:12345,packDigest,nowMs};
}
const denied=(a)=>assert.throws(()=>verifyExternalAppGateReceipts(a),
 /independent_external_app_gate_denied/);
test('five distinct independent source gate claims bind exact HEAD, CI and pack',()=>{
 const verified=verifyExternalAppGateReceipts(args());
 assert.deepEqual(Object.keys(verified.gates),FIXED);
 for(const gate of FIXED)
  assert.deepEqual(verified.gates[gate],{
   headSha:head,verdict:'passed',
   evidenceId:'verified-'+gate.replaceAll('_','-')+'-proof'
  });
 assert.equal(verified.validUntilMs,nowMs+120000);
 assert.equal(verified.physicalEvidenceAudited,false);
 assert.equal(verified.independentProducerInstalled,false);
});
test('missing, duplicate, reordered or forged gate records fail closed',()=>{
 const original=bundle(),tamper=(fn)=>{
  const p=JSON.parse(JSON.stringify(original));fn(p);return p;
 };
 for(const bad of [
  tamper(p=>p.receipts.pop()),
  tamper(p=>p.receipts.push(p.receipts[0])),
  tamper(p=>p.receipts.reverse()),
  tamper(p=>{p.receipts[0].gate='pc';}),
  tamper(p=>{p.receipts[0].signatureBase64='a'.repeat(88);}),
  tamper(p=>{p.receipts[0].claimJson=p.receipts[0].claimJson+' ';}),
  tamper(p=>{p.receipts[1].claimJson=p.receipts[0].claimJson;}),
  tamper(p=>{p.scope='other';})
 ])denied(args(bad));
});
test('source/role key substitution and signing domain confusion fail',()=>{
 const f=args();
 for(const change of [
  {devicePublicKeyPem:pem(outsider)},
  {rootPublicKeyPem:pem(outsider)},
  {devicePublicKeyPem:pem(root)},
  {rootPublicKeyPem:pem(device)},
  {reviewerPublicKeyPem:pem(device)},
  {approvalPublicKeyPem:pem(root)},
  {codexPublicKeyPem:pem(root)},
  {rootPublicKeyPem:pem(reviewer)}
 ])denied({...f,...change});
 const p=bundle();p.receipts[0].signatureBase64=signClaim(
  device,ROOT_GATE_DOMAIN,p.receipts[0].claimJson);
 denied(args(p));
});
test('stale, mismatched or unsigned proofs cannot become accepted gates',()=>{
 const f=args();
 for(const bad of [
  {...f,head:'d'.repeat(40)}, {...f,base:'e'.repeat(40)},
  {...f,ciRunId:12346},{...f,packDigest:'f'.repeat(64)},
  {...f,nowMs:nowMs+120001},
  {...f,raw:f.raw+'\n'},
  {...f,rootPublicKeyPem:undefined},
  {...f,devicePublicKeyPem:undefined}
 ])denied(bad);
});
test('per-gate unique proof digests and 30-minute max lifetime required',()=>{
 const p=bundle(),rootClaims=p.receipts[3];
 function mutate(i,patch,signer,domain){
  const v=JSON.parse(p.receipts[i].claimJson);
  Object.assign(v,patch);
  p.receipts[i].claimJson=JSON.stringify(v);
  p.receipts[i].signatureBase64=signClaim(signer,domain,p.receipts[i].claimJson);
 }
 mutate(3,{proofDigest:JSON.parse(p.receipts[0].claimJson).proofDigest},
  root,ROOT_GATE_DOMAIN);
 denied(args(p));
 mutate(3,{proofDigest:sha('different'),expiresAtMs:nowMs+1800001},
  root,ROOT_GATE_DOMAIN);
 denied(args(p));
 mutate(3,{expiresAtMs:nowMs+30000,verdict:'blocked'},
  root,ROOT_GATE_DOMAIN);
 denied(args(p));
 assert.ok(rootClaims.gate==='root_security');
});
