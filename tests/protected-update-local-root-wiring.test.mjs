import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {collectFixedLocalBootstrapAttestations}
 from '../scripts/protected-update-issuer-collect.mjs';
import {bootstrapOneShotFixedRoot}
 from '../scripts/protected-update-bootstrap-entry.mjs';
import {provisionIndependentProtectedIssuersOnce}
 from '../scripts/protected-update-issuer-provision.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
import {selectFixedIssuerSourceRows}
 from '../scripts/protected-update-issuer-stage.mjs';

test('C local trust source has exact static package and fixed OS role closure',()=>{
 const required=[
  'scripts/protected-update-local-review-issuer.mjs',
  'scripts/protected-update-local-approval-issuer.mjs',
  'src/ops/protected-update-local-issuer-claims.mjs',
  'src/ops/protected-update-local-trust-contract.mjs'
 ];
 for(const name of required)assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(name));
 const selected=selectFixedIssuerSourceRows(PROTECTED_BOOTSTRAP_FILES.map(path=>({
  path,bytes:100,sha256:'a'.repeat(64)
 }))).map(f=>f.path);
 for(const name of required.slice(0,3))assert.ok(selected.includes(name));
 assert.ok(!selected.includes('src/ops/protected-update-local-trust-contract.mjs'));
});
test('direct checkout cannot provision, issue local trust or migrate original',async()=>{
 assert.throws(provisionIndependentProtectedIssuersOnce,
  /protected_issuer_provision_denied_or_unknown/);
 await assert.rejects(collectFixedLocalBootstrapAttestations(),
  /protected_issuer_collect_denied_or_unknown/);
 await assert.rejects(bootstrapOneShotFixedRoot(),
  /protected_bootstrap_entry_denied/);
});
test('local mode cannot silently replace existing protected GitHub Bot branch',()=>{
 const collector=readFileSync(new URL(
  '../scripts/protected-update-issuer-collect.mjs',import.meta.url),'utf8');
 const bootstrap=readFileSync(new URL(
  '../scripts/protected-update-bootstrap-entry.mjs',import.meta.url),'utf8');
 const provision=readFileSync(new URL(
  '../scripts/protected-update-issuer-provision.mjs',import.meta.url),'utf8');
 assert.ok(collector.includes("rootString('signer-mode',64)"));
 assert.ok(collector.includes("if(signerMode==='wsl-local-v1')return 'local-bootstrap'"));
 assert.ok(collector.includes("if(signerMode!=='external-v1')deny()"));
 assert.ok(bootstrap.includes(
  "if(signerMode!=='wsl-local-v1'&&signerMode!=='external-v1')fail()"));
 assert.ok(bootstrap.includes("if(!localMode){"));
 assert.ok(bootstrap.includes("fetchAndVerifyOfficialReviewerApproval({"));
 assert.ok(bootstrap.includes("verifyLocalProtectedBootstrapContract({"));
 assert.ok(provision.includes("validatePinnedProtectedSignerMode(trust('signer-mode',64))"));
});
test('local signing collection records replay fence before first role dispatch',()=>{
 const src=readFileSync(new URL(
  '../scripts/protected-update-issuer-collect.mjs',import.meta.url),'utf8');
 const body=src.split('export async function collectFixedLocalBootstrapAttestations(){')[1]
  ?.split('/** Bound routine signer orchestration')[0];
 assert.ok(body);
 const fence=body.indexOf("writeRoot(TRUST+'/local-bootstrap-dispatch.intent.json'");
 const reviewer=body.indexOf("'protected-update-local-review-issuer.mjs','reviewer'");
 const approver=body.indexOf("'protected-update-local-approval-issuer.mjs','approval'");
 assert.ok(fence>0&&reviewer>fence&&approver>reviewer);
 assert.ok(body.includes('verifyLocalProtectedBootstrapContract({'));
 assert.ok(body.includes('githubEvidence:await current()'));
 assert.ok(body.includes('safeToRetry:false'));
});

test('Option C routine route requires root-pinned mode, signed issuer and live HEAD evidence',()=>{
 const get=rel=>readFileSync(new URL('../'+rel,import.meta.url),'utf8');
 const root=get('scripts/protected-update-root-apply.mjs');
 const stage=get('src/ops/protected-update-routine-stage.mjs');
 const collect=get('scripts/protected-update-issuer-collect.mjs');
 const runtime=get('src/ops/protected-update-issuer-runtime.mjs');
 for(const [s,fragment] of [
  [root,"rootPinnedSignerMode()==='wsl-local-v1'"],
  [root,"preflightAuthenticatedProtectedUpdate({"],
  [root,"verifyOperationalReviewer(finalNowMs)"],
  [stage,"pinnedSignerMode()==='wsl-local-v1'"],
  [stage,"acquireRoutineDispatchFence("],
  [collect,"const localMode=signerMode==='wsl-local-v1'"],
  [collect,"assembleCollectedRoutineAuthorization({"],
  [runtime,"if(context.signerMode==='wsl-local-v1')"]
 ])assert.ok(s.includes(fragment),fragment);
 assert.ok(root.includes("localMode?null:await fetchAndVerifyOfficialReviewerApproval"));
 assert.ok(collect.includes('fetchAndVerifyGitHubBootstrapEvidence({'));
 assert.ok(stage.includes('fetchAndVerifyGitHubControllerPair({'));
});
