import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {Script} from 'node:vm';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
import {verifyCodexOSProvisionPlan,provisionCodexSignerOSOnce,
  PROTECTED_CODEX_KEYGEN_PROGRAM}
  from '../scripts/protected-update-codex-os-provision.mjs';
const denied=fn=>assert.throws(fn,
  /protected_codex_os_provision_denied_or_unknown/);
const h='a'.repeat(40);
test('C-mode Codex provisioner included in exact immutable source packet',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
   'scripts/protected-update-codex-os-provision.mjs'));
});
test('pure admission shape denies fake/missing/unsafe root provisioning claims',()=>{
 const good={head:h,approvedHead:h,packVerified:true,
   workerUid:1000,workerGid:1000};
 const result=verifyCodexOSProvisionPlan(good);
 assert.equal(result.ownerApproved,false);
 assert.equal(result.retrySafe,false);
 assert.equal(result.authorizationIssued,false);
 for(const bad of [
  {...good,head:'x'}, {...good,approvedHead:'b'.repeat(40)},
  {...good,packVerified:false},{...good,workerUid:0},
  {...good,workerGid:0},{}
 ])denied(()=>verifyCodexOSProvisionPlan(bad));
});
test('mutable checkout may not create a Codex signing OS principal',()=>{
 denied(()=>provisionCodexSignerOSOnce());
 const path=fileURLToPath(new URL(
  '../scripts/protected-update-codex-os-provision.mjs',import.meta.url));
 const r=spawnSync(process.execPath,[path],{
  encoding:'utf8',timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,1);
 assert.match(r.stderr,/protected_codex_os_provision_denied_or_unknown/);
 assert.equal(r.stdout,'');
});
test('fixed child keygen has no caller-controlled output path',()=>{
 assert.doesNotThrow(()=>new Script(PROTECTED_CODEX_KEYGEN_PROGRAM));
 const r=spawnSync(process.execPath,[
  '-e',PROTECTED_CODEX_KEYGEN_PROGRAM,'/tmp/arbitrary-key'
 ],{encoding:'utf8',timeout:5000,maxBuffer:1024});
 assert.equal(r.status,50);
 assert.equal(r.stdout,'');
});
test('trusted owner metadata, immutable sources and binary hashes precede useradd',()=>{
 const src=readFileSync(new URL(
  '../scripts/protected-update-codex-os-provision.mjs',import.meta.url),'utf8');
 const start=src.indexOf('export function provisionCodexSignerOSOnce()');
 const trusted=src.indexOf("trusted('approved-pack-digest'",start);
 const complete=src.indexOf('verifyProtectedBootstrapPack(',trusted);
 const binary=src.indexOf('verifyExec(path,',complete);
 const absent=src.indexOf('missingIdentity()',binary);
 const created=src.indexOf("spawnSync('/usr/sbin/useradd'",absent);
 assert.ok(start>=0&&trusted>start&&complete>trusted&&
  binary>complete&&absent>binary&&created>absent);
 assert.match(src,/assertFixedCodexSignerPrerequisites\(\)/);
 assert.match(src,/safeToRetry:false/);
 assert.doesNotMatch(src,/NOPASSWD:ALL|chmodSync\(.*0o777/);
});
