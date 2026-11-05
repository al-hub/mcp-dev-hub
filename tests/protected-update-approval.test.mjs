import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash, generateKeyPairSync, sign} from 'node:crypto';
import {APPROVAL_DOMAIN, verifySignedProtectedUpdateApproval}
  from '../src/ops/protected-update-approval.mjs';
const head='a'.repeat(40),base='b'.repeat(40);
const id='c'.repeat(32),digest='d'.repeat(64),now=1793900000000;
const pair=generateKeyPairSync('ed25519');
const publicPem=pair.publicKey.export({type:'spki',format:'pem'});
const manifestJson=JSON.stringify({
  version:1,repository:'al-hub/mcp-dev-hub',commit:head,
  bundle:'controller-pair',files:[
    {name:'ai-github-canary-policy.mjs',sha256:'e'.repeat(64),bytes:124},
    {name:'ai-github-canary.mjs',sha256:'f'.repeat(64),bytes:456}
  ]
});
const baseApproval=()=>({
  version:1,repository:'al-hub/mcp-dev-hub',scope:'controller-pair',
  head,base,manifestSha256:createHash('sha256').update(manifestJson).digest('hex'),
  ciRunId:42024048411,ciHead:head,reviewHead:head,reviewBase:base,
  reviewDigest:digest,reviewVerdict:'PASS',operationId:id,
  issuedAtMs:now-1000,expiresAtMs:now+10000
});
const invoke=(value=baseApproval(),overrides={})=>{
  const approvalJson=typeof value==='string'?value:JSON.stringify(value);
  const signatureBase64=sign(null,Buffer.from(APPROVAL_DOMAIN+approvalJson),
    pair.privateKey).toString('base64');
  return verifySignedProtectedUpdateApproval({
    manifestJson,approvalJson,signatureBase64,trustPublicKeyPem:publicPem,
    trustedHead:head,trustedBase:base,trustedOperationId:id,nowMs:now,
    ...overrides
  });
};
test('signed bounded, exact-head/base approval returns immutable metadata only',()=>{
  const result=invoke();
  assert.equal(result.head,head);
  assert.equal(result.manifest.files.length,2);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.manifest));
});
test('unsigned, substituted key, tampered signature or payload is denied',()=>{
  const json=JSON.stringify(baseApproval());
  assert.throws(()=>invoke(baseApproval(),{signatureBase64:'AA=='}),/invalid_protected_approval/);
  const other=generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});
  assert.throws(()=>invoke(baseApproval(),{trustPublicKeyPem:other}),/invalid_approval_signature/);
  const signature=sign(null,Buffer.from(APPROVAL_DOMAIN+json),pair.privateKey)
    .toString('base64');
  assert.throws(()=>invoke(baseApproval(),{approvalJson:json.replace('PASS','FAIL'),
    signatureBase64:signature}),/invalid_protected_approval/);
});
test('rejects stale SHA, mismatched operation journal ID and modified bytes',()=>{
  assert.throws(()=>invoke(baseApproval(),{trustedHead:'3'.repeat(40)}),/invalid_protected_approval/);
  assert.throws(()=>invoke(baseApproval(),{trustedBase:'4'.repeat(40)}),/invalid_protected_approval/);
  assert.throws(()=>invoke(baseApproval(),{trustedOperationId:'5'.repeat(32)}),/invalid_protected_approval/);
  assert.throws(()=>invoke(baseApproval(),{manifestJson:manifestJson+' '}),/invalid_protected_approval/);
});
test('rejects fabricated review or CI linkage even when self-signed in fixture',()=>{
  for(const mutation of [
    {reviewVerdict:'WARN'},{ciHead:base},{reviewHead:base},
    {reviewBase:head},{reviewDigest:'bad'},{ciRunId:0},
    {scope:'any'},{repository:'evil/repo'},{version:2}
  ]) assert.throws(()=>invoke({...baseApproval(),...mutation}),/invalid_protected_approval/);
});
test('canonical JSON forbids duplicate keys, extra fields and prototype keys',()=>{
  const raw=JSON.stringify(baseApproval());
  for(const bad of [
    raw.replace('{"version":1','{"version":1,"version":1'),
    raw.replace('{"version":1','{"__proto__":true,"version":1'),
    raw.replace('{"version":1','{ "version":1'),
    JSON.stringify({...baseApproval(),shell:'id'})
  ]) assert.throws(()=>invoke(bad),/invalid_protected_approval/);
});
test('time window and replay-expired evidence fail closed',()=>{
  for(const mutation of [
    {issuedAtMs:now+1},{expiresAtMs:now-1},
    {expiresAtMs:now+600001},{issuedAtMs:now,expiresAtMs:now},
    {expiresAtMs:'tomorrow'}
  ]) assert.throws(()=>invoke({...baseApproval(),...mutation}),/invalid_protected_approval/);
});
test('no trust key, non-Ed25519 trust key and unbounded approval are rejected',()=>{
  assert.throws(()=>invoke(baseApproval(),{trustPublicKeyPem:'invalid'}),/invalid_trust_key/);
  assert.throws(()=>invoke('x'.repeat(2100)),/invalid_protected_approval/);
});
