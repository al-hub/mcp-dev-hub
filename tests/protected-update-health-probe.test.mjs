import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PROTECTED_HEALTH_UNIT_NAMES,evaluateProtectedHealthEvidence,
  observeProtectedWorkerHealth
} from '../src/ops/protected-update-health-probe.mjs';

function healthy(){
  return {
    services:PROTECTED_HEALTH_UNIT_NAMES.map(service=>({
      service,status:0,output:'active'
    })),
    controllerSyntax:{status:0},policySyntax:{status:0}
  };
}
test('synthetic fixed user-services and parsing can form only evidence, not authority',()=>{
  assert.equal(evaluateProtectedHealthEvidence(healthy()),true);
});
test('unhealthy services fail while syntax remains clean',()=>{
  for(let i=0;i<2;i++){
    const r=healthy();
    r.services[i]={...r.services[i],status:3,output:'inactive'};
    assert.equal(evaluateProtectedHealthEvidence(r),false);
  }
});
test('syntax errors on current controller or policy fail closed',()=>{
  for(const field of ['controllerSyntax','policySyntax']){
    const r=healthy();r[field].status=1;
    assert.equal(evaluateProtectedHealthEvidence(r),false);
  }
});
test('synthetic service substitutions cannot be made authoritative',()=>{
  const r=healthy();
  r.services[0].service='attacker-injected.service';
  assert.equal(evaluateProtectedHealthEvidence(r),false);
});
test('malformed or absent proof does not return a false PASS',()=>{
  for(const r of [{},{services:[]},{services:[null,null]}])
    assert.equal(evaluateProtectedHealthEvidence(r),false);
});
test('nonroot caller is denied before reading any OS state',()=>{
  if(process.geteuid?.()!==0)
    assert.throws(()=>observeProtectedWorkerHealth({
      pinnedWorkerUid:1000,pinnedWorkerGid:1000,
      expectedCommit:'a'.repeat(40),
      expectedHashes:{'ai-github-canary.mjs':'c'.repeat(64)}
    }),/protected_health_observer_unknown/);
});
