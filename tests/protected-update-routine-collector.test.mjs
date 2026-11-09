import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {collectFixedRoutineIssuerAttestations}
 from '../scripts/protected-update-issuer-collect.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
test('source-only routine collector cannot be imported and dispatched as root',async()=>{
 await assert.rejects(collectFixedRoutineIssuerAttestations({
  intent:{version:2}
 }),/protected_issuer_collect_denied_or_unknown/);
});
test('root apply still rejects direct invocation from mutable checkout',()=>{
 const root=fileURLToPath(new URL('../scripts/protected-update-root-apply.mjs',
  import.meta.url));
 const r=spawnSync(process.execPath,[root],{
  input:JSON.stringify({version:2}),encoding:'utf8',
  timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,1);
 assert.equal(r.stdout,'');
});
test('collector, root dispatcher and package closure are pinned',()=>{
 for(const f of [
  'scripts/protected-update-issuer-collect.mjs',
  'scripts/protected-update-root-apply.mjs',
  'src/ops/protected-update-routine-stage.mjs',
  'src/ops/protected-update-routine-collection.mjs',
  'src/ops/protected-update-routine-intent.mjs'
 ])assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(f));
});
