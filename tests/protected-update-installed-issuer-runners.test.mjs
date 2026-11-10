import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {issueFixedIndependentBootstrapReview}
  from '../scripts/protected-update-review-issuer.mjs';
import {issueFixedIndependentBootstrapApproval}
  from '../scripts/protected-update-approval-issuer.mjs';
import {assertRoleRuntimeInstalled}
  from '../src/ops/protected-update-issuer-runtime.mjs';
import {issueFixedLocalBootstrapReview}
  from '../scripts/protected-update-local-review-issuer.mjs';
import {issueFixedLocalBootstrapApproval}
  from '../scripts/protected-update-local-approval-issuer.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const bad=/protected_signer_runtime_denied/;
test('issuer executables and shared trusted network/role code are in exact package',()=>{
  for(const name of [
    'scripts/protected-update-review-issuer.mjs',
    'scripts/protected-update-approval-issuer.mjs',
    'src/ops/protected-update-issuer-runtime.mjs',
    'src/ops/protected-update-bootstrap-issuer.mjs',
    'src/ops/protected-update-local-issuer-claims.mjs',
    'src/ops/protected-update-local-trust-contract.mjs',
    'scripts/protected-update-local-review-issuer.mjs',
    'scripts/protected-update-local-approval-issuer.mjs'
  ])assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(name));
});
test('review signer imported from checkout rejects role impersonation',async()=>{
  await assert.rejects(issueFixedIndependentBootstrapReview(),bad);
});
test('approval signer imported from checkout rejects role impersonation',async()=>{
  await assert.rejects(issueFixedIndependentBootstrapApproval(),bad);
});
test('role runtime rejects any arbitrary issuer entry path',()=>{
  for(const role of ['reviewer','approval','root','worker']){
    assert.throws(()=>assertRoleRuntimeInstalled({
      role,moduleUrl:import.meta.url,argv:['node','/tmp/false']
    }),bad);
  }
});
test('both issuer direct CLI executions fail rather than sign from checkout',()=>{
  for(const name of [
    'protected-update-review-issuer.mjs',
    'protected-update-approval-issuer.mjs'
  ]){
    const script=fileURLToPath(new URL('../scripts/'+name,import.meta.url));
    const r=spawnSync(process.execPath,[script],{
      encoding:'utf8',input:'',timeout:5000,maxBuffer:1024
    });
    assert.equal(r.status,1);
    assert.equal(r.stdout,'');
    assert.match(r.stderr,/issuer_denied_or_unknown/);
  }
});
test('Worker-supplied reviewer verdict JSON cannot enter either signer CLI',()=>{
  const script=fileURLToPath(new URL(
    '../scripts/protected-update-review-issuer.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[
    script,'--verdict=PASS','--head='+'a'.repeat(40)
  ],{encoding:'utf8',input:'{"verdict":"PASS"}',
    timeout:5000,maxBuffer:1024});
  assert.equal(r.status,1);
  assert.equal(r.stdout,'');
});

test('two fixed Option C issuer scripts cannot sign from mutable checkout',async()=>{
 await assert.rejects(issueFixedLocalBootstrapReview(),bad);
 await assert.rejects(issueFixedLocalBootstrapApproval(),bad);
 for(const [name,error] of [
  ['protected-update-local-review-issuer.mjs',
   /protected_local_reviewer_denied_or_unknown/],
  ['protected-update-local-approval-issuer.mjs',
   /protected_local_approver_denied_or_unknown/]
 ]){
  const script=fileURLToPath(new URL('../scripts/'+name,import.meta.url));
  const r=spawnSync(process.execPath,[script],{
   encoding:'utf8',input:'{"verdict":"PASS"}',timeout:5000,maxBuffer:1024
  });
  assert.equal(r.status,1);
  assert.equal(r.stdout,'');
  assert.match(r.stderr,error);
 }
});
