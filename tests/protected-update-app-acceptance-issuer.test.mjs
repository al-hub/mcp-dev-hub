import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {issueFixedIndependentAppAcceptanceApproval}
 from '../scripts/protected-update-app-acceptance-approval-issuer.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
import {selectFixedIssuerSourceRows}
 from '../scripts/protected-update-issuer-stage.mjs';

const script='scripts/protected-update-app-acceptance-approval-issuer.mjs';
const moduleName='src/ops/protected-update-app-acceptance.mjs';
test('fixed acceptance signer and verifier have immutable package + role closure',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(script));
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(moduleName));
 const rows=selectFixedIssuerSourceRows(PROTECTED_BOOTSTRAP_FILES.map(path=>({
  path,bytes:100,sha256:'a'.repeat(64)
 })));
 assert.ok(rows.some(r=>r.path===script));
 assert.ok(rows.some(r=>r.path===moduleName));
});
test('imported acceptance signer rejects an uninstalled mutable checkout',async()=>{
 await assert.rejects(issueFixedIndependentAppAcceptanceApproval(),
  /protected_signer_runtime_denied/);
});
test('direct checkout CLI cannot sign a packet or mint a PASS',()=>{
 const entry=fileURLToPath(new URL('../'+script,import.meta.url));
 const r=spawnSync(process.execPath,[entry],{
  encoding:'utf8',timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,78);
 assert.equal(r.stdout,'');
 assert.match(r.stderr,/protected_app_acceptance_issuer_denied/);
});
test('untrusted extra payload/CLI args cannot turn checkout into a signer',()=>{
 const entry=fileURLToPath(new URL('../'+script,import.meta.url));
 const r=spawnSync(process.execPath,[entry,'--head='+'a'.repeat(40)],{
  input:JSON.stringify({verdict:'PASS'}),encoding:'utf8',
  timeout:5000,maxBuffer:1024
 });
 assert.equal(r.status,78);
 assert.equal(r.stdout,'');
});
