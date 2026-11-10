import test from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyProtectedIssuerIsolationEvidence,assertFixedOperationalIssuerIsolation,
  pinnedIssuerNumericTrustName
} from '../src/ops/protected-update-issuer-boundary.mjs';

const denied=fn=>assert.throws(fn,/protected_issuer_isolation_denied/);
function fixture(){
  const row=()=>({uid:0,mode:0o755,directory:true,symlink:false});
  const identity=(uid,gid)=>({
    uid,gid,dir:{uid,mode:0o700,directory:true,symlink:false},
    key:{uid,mode:0o400,regular:true,symlink:false,links:1,bytes:119}
  });
  return {reviewer:identity(201,201),approval:identity(202,202),
    workerUid:1000,workerGid:1000,
    parentRows:[row(),row(),row(),row(),row(),row(),row()]};
}
test('distinct issuer owners, directories, keys and worker form only an OS boundary',()=>{
  const evidence=verifyProtectedIssuerIsolationEvidence(fixture());
  assert.equal(evidence.state,'os_private_key_metadata_separated');
  assert.equal(evidence.installerAuthorized,false);
  assert.equal(evidence.signerProvenanceVerified,false);
});
test('same owner or shared signing group is refused',()=>{
  const r=fixture();r.approval.uid=r.reviewer.uid;denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  const s=fixture();s.approval.gid=s.reviewer.gid;denied(()=>verifyProtectedIssuerIsolationEvidence(s));
});
test('either issuer sharing the Worker account is denied',()=>{
  for(const role of ['reviewer','approval']){
    const r=fixture();r[role].uid=1000;
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});
test('world or group readable/modified private key is denied',()=>{
  for(const mode of [0o440,0o444,0o600,0o640,0o777]){
    const r=fixture();r.reviewer.key.mode=mode;
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});
test('symlink, hardlink, or nonregular issuer secret cannot be trusted',()=>{
  for(const patch of [{symlink:true},{links:2},{regular:false},
    {bytes:0},{bytes:100000}]){
    const r=fixture();Object.assign(r.approval.key,patch);
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});
test('writable or symlinked issuer parent directory is refused',()=>{
  for(const patch of [{mode:0o777},{symlink:true},{uid:1000},
    {directory:false}]){
    const r=fixture();Object.assign(r.parentRows[3],patch);
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});
test('issuer private directory must be exactly owner-private',()=>{
  for(const patch of [{mode:0o755},{mode:0o770},
    {symlink:true},{uid:0}]){
    const r=fixture();Object.assign(r.reviewer.dir,patch);
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});
test('unprivileged caller cannot inspect root secret metadata as authority',()=>{
  if(process.geteuid?.()!==0)
    denied(()=>assertFixedOperationalIssuerIsolation());
});

test('signer account cannot share Worker primary group',()=>{
  for(const role of ['reviewer','approval']){
    const fixtureData=fixture();
    fixtureData[role].gid=fixtureData.workerGid;
    denied(()=>verifyProtectedIssuerIsolationEvidence(fixtureData));
  }
});
test('root trust ancestors cannot be writable or symlinked',()=>{
  for(const patch of [{mode:0o777},{symlink:true},{uid:1000}]){
    const r=fixture();Object.assign(r.parentRows[5],patch);
    denied(()=>verifyProtectedIssuerIsolationEvidence(r));
  }
});

test('fixed root trust filenames distinguish UID and GID without suffix duplication',()=>{
  for(const role of ['worker','reviewer','approval']){
    assert.equal(pinnedIssuerNumericTrustName(role,'uid'),role+'-uid');
    assert.equal(pinnedIssuerNumericTrustName(role,'gid'),role+'-gid');
  }
  for(const [role,kind] of [['other','uid'],['worker','other'],
    ['../worker','gid'],['reviewer',null]])
    denied(()=>pinnedIssuerNumericTrustName(role,kind));
});

test('C mode fails closed unless Codex key is held by a third OS principal',()=>{
 const f=fixture();
 const signer={
  uid:203,gid:203,dir:{uid:203,gid:203,mode:0o700,directory:true,symlink:false},
  key:{uid:203,gid:203,mode:0o400,regular:true,symlink:false,links:1,bytes:119}
 };
 const local={...f,localMode:true,codex:signer,
  codexParents:[{uid:0,mode:0o755,directory:true,symlink:false}]};
 const good=verifyProtectedIssuerIsolationEvidence(local);
 assert.equal(good.codexUid,203);
 for(const p of [
  {codex:{...signer,uid:1000}},
  {codex:{...signer,gid:1000}},
  {codex:{...signer,uid:201}},
  {codex:{...signer,gid:202}},
  {codex:{...signer,key:{...signer.key,mode:0o440}}},
  {codex:{...signer,dir:{...signer.dir,mode:0o755}}},
  {codexParents:[{uid:1000,mode:0o755,directory:true,symlink:false}]},
  {codex:null}
 ])denied(()=>verifyProtectedIssuerIsolationEvidence({...local,...p}));
});
