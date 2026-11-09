import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {
  selectFixedIssuerSourceRows,stagePinnedIssuerRuntimeOnce
} from '../scripts/protected-update-issuer-stage.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';
const DENIED=/protected_issuer_staging_denied_or_unknown/;
const expected=[
  'scripts/protected-update-review-issuer.mjs',
  'scripts/protected-update-approval-issuer.mjs',
  'scripts/protected-update-routine-review-issuer.mjs',
  'scripts/protected-update-routine-approval-issuer.mjs',
  'scripts/protected-update-app-acceptance-approval-issuer.mjs',
  'src/ops/protected-update-bootstrap-issuer.mjs',
  'src/ops/protected-update-routine-issuer.mjs',
  'src/ops/protected-update-approval.mjs',
  'src/ops/protected-update-manifest.mjs',
  'src/ops/protected-update-install-attestation.mjs',
  'src/ops/protected-update-issuer-runtime.mjs',
  'src/ops/protected-update-github-evidence.mjs',
  'src/ops/protected-update-app-acceptance.mjs'
];
const files=()=>PROTECTED_BOOTSTRAP_FILES.map(path=>({
  path,sha256:'a'.repeat(64),bytes:100
}));
test('issuer stage source closure is fixed to thirteen least-privilege reviewed files',()=>{
  const rows=selectFixedIssuerSourceRows(files());
  assert.deepEqual(rows.map(f=>f.path),expected);
  assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
    'scripts/protected-update-issuer-stage.mjs'));
});
test('issuer stage rejects absent, duplicate and spoofed source closure entries',()=>{
  const base=files();
  for(const wrong of [
    base.filter(f=>f.path!==expected[0]),
    [...base,{...base.find(f=>f.path===expected[0])}],
    base.map(f=>f.path===expected[2]?{...f,sha256:'invalid'}:f),
    base.map(f=>f.path===expected[3]?{...f,bytes:0}:f),
    []
  ])assert.throws(()=>selectFixedIssuerSourceRows(wrong),DENIED);
});
test('nonroot source checkout may never stage privileged issuer runtime',()=>{
  assert.throws(stagePinnedIssuerRuntimeOnce,DENIED);
});
test('direct checkout execution cannot create root-owned code tree',()=>{
  const path=fileURLToPath(new URL(
    '../scripts/protected-update-issuer-stage.mjs',import.meta.url));
  const r=spawnSync(process.execPath,[path],{
    encoding:'utf8',timeout:5000,maxBuffer:2048
  });
  assert.equal(r.status,1);
  assert.match(r.stderr,DENIED);
  assert.equal(r.stdout,'');
});
