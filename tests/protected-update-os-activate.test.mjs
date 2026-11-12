import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  activateProtectedOSOnce,validateFixedActivationEvidence,
  assertNoResidualSupplementaryGroups
} from '../scripts/protected-update-os-activate.mjs';
import {renderFixedProtectedSudoPolicy}
  from '../src/ops/protected-update-sudo-policy.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const denied=fn=>assert.throws(fn,/protected_os_activation_denied_or_unknown/);
const HEAD='b'.repeat(40);
const policy=()=>renderFixedProtectedSudoPolicy({workerAccount:'synthetic_worker'});
test('install candidate and exact sudo policy are in pinned source pack',()=>{
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-os-activate.mjs'));
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'src/ops/protected-update-sudo-policy.mjs'));
});
test('root activation health child rejects inherited supplementary groups',()=>{
  assert.equal(assertNoResidualSupplementaryGroups({actual:[],expected:0}),true);
  // On Linux Node may include the effective GID itself.
  assert.equal(assertNoResidualSupplementaryGroups({actual:[0],expected:0}),true);
  for(const actual of [[0,0],[0,10],[10],['0'],null,undefined,{}])
    denied(()=>assertNoResidualSupplementaryGroups({actual,expected:0}));
  denied(()=>assertNoResidualSupplementaryGroups({actual:[],expected:10}));
});
test('health PASS alone never installs: admission remains explicit NO-GO',()=>{
  const r=validateFixedActivationEvidence({
    bootstrapPhase:'migrated_pending_live_health',
    baselineCommit:HEAD,health:true,policy:policy()
  });
  assert.equal(r.phase,'ready_for_sudo_rule_activation');
  assert.equal(r.safeToRetry,false);
});
test('health false or unknown always refuses the sudo authorization',()=>{
  for(const health of [false,null,'unknown','healthy',0])
    denied(()=>validateFixedActivationEvidence({
      bootstrapPhase:'migrated_pending_live_health',
      baselineCommit:HEAD,health,policy:policy()
    }));
});
test('wrong baseline, missing wrapper stage or privileged policy refused',()=>{
  const p=policy();
  for(const args of [
    {bootstrapPhase:'unknown',baselineCommit:HEAD,health:true,policy:p},
    {bootstrapPhase:'migrated_pending_live_health',
      baselineCommit:'bad',health:true,policy:p},
    {bootstrapPhase:'migrated_pending_live_health',
      baselineCommit:HEAD,health:true,policy:{...p,unrestrictedSudo:true}},
    {bootstrapPhase:'migrated_pending_live_health',
      baselineCommit:HEAD,health:true,policy:{...p,mode:0o666}},
    {bootstrapPhase:'migrated_pending_live_health',
      baselineCommit:HEAD,health:true,policy:null}
  ])denied(()=>validateFixedActivationEvidence(args));
});
test('root activation API cannot operate from an untrusted checkout',async()=>{
  await assert.rejects(activateProtectedOSOnce(),
    /protected_os_activation_denied_or_unknown/);
});
test('direct source-checkout installer invocation denies without root writes',()=>{
  const src=fileURLToPath(new URL(
    '../scripts/protected-update-os-activate.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[src],{
    encoding:'utf8',input:'',timeout:5000,maxBuffer:4096
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,/protected_os_activation_denied_or_unknown/);
  assert.equal(r.stdout,'');
});
