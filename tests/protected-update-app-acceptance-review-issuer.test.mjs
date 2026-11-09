import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {assembleAppAcceptanceReviewerPacket,
 issueFixedIndependentAppAcceptanceReview}
 from '../scripts/protected-update-app-acceptance-review-issuer.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
 from '../scripts/protected-update-bootstrap-pack.mjs';
import {selectFixedIssuerSourceRows}
 from '../scripts/protected-update-issuer-stage.mjs';

const head='a'.repeat(40),base='b'.repeat(40),packDigest='c'.repeat(64);
const NOW=1900000000000, RUN=12345;
const context={head,base,packDigest,ciRunId:RUN,prNumber:39};
const gh={head,base,ciRunId:RUN,ciPassed:true,strictProtection:true};
const codex={reviewDigest:'d'.repeat(64),expiresAtMs:NOW+120000};
const external=()=>({
 validUntilMs:NOW+100000,
 gates:Object.fromEntries(['private_sse','pc','galaxy',
  'root_security','original_restore'].map(g=>[
  g,{headSha:head,verdict:'passed',evidenceId:'verified-'+g+'-proof'}
 ]))
});
const make=(override={})=>assembleAppAcceptanceReviewerPacket({
 context,githubEvidence:gh,codex,external:external(),
 nowMs:NOW,...override
});
test('review packet is narrow, canonical, bounded and has no invented Bot approval',()=>{
 const raw=make(),p=JSON.parse(raw);
 assert.equal(JSON.stringify(p),raw);
 assert.equal(p.head,head);
 assert.equal(p.base,base);
 assert.equal(p.ciRunId,RUN);
 assert.equal(p.evidence.reviewReadonly,true);
 assert.equal(p.evidence.reviewIsolated,true);
 assert.equal(p.evidence.authorAgent,'agy');
 assert.equal(p.evidence.gates.pc.evidenceId,'verified-pc-proof');
 assert.equal(p.evidence.gates.ci.evidenceId,'verified-ci-12345');
 assert.equal(p.protectionEvidence.requiredApprovals,0);
 assert.equal(p.protectionEvidence.reviewRuleAbsent,true);
 assert.equal(p.expiresAtMs,NOW+90000);
 assert.ok(Buffer.byteLength(raw)<12000);
 assert.equal(Object.hasOwn(p,'reviewSubmitted'),false);
});
test('assembler refuses absent, blocked, expired or mismatched independently verified inputs',()=>{
 const denied=x=>assert.throws(()=>make(x),
  /protected_app_acceptance_review_denied/);
 for(const changed of [
  {githubEvidence:{...gh,ciPassed:false}},
  {githubEvidence:{...gh,strictProtection:false}},
  {githubEvidence:{...gh,head:'f'.repeat(40)}},
  {githubEvidence:{...gh,base:'f'.repeat(40)}},
  {githubEvidence:{...gh,ciRunId:RUN+1}},
  {codex:{...codex,expiresAtMs:NOW}},
  {codex:{...codex,reviewDigest:'forged'}},
  {external:{...external(),validUntilMs:NOW}},
  {external:{...external(),gates:{pc:{headSha:head}}}},
  {external:{...external(),gates:{...external().gates,extra:{}}}},
  {nowMs:0}
 ])denied(changed);
});
test('source-only checkout cannot act as independent reviewer signer',async()=>{
 await assert.rejects(issueFixedIndependentAppAcceptanceReview(),
  /protected_signer_runtime_denied/);
 const entry=fileURLToPath(new URL(
  '../scripts/protected-update-app-acceptance-review-issuer.mjs',
  import.meta.url));
 const run=spawnSync(process.execPath,[entry],{
  encoding:'utf8',timeout:6000,maxBuffer:2048
 });
 assert.equal(run.status,78);
 assert.equal(run.stdout,'');
 assert.match(run.stderr,/protected_app_acceptance_review_denied/);
 const extra=spawnSync(process.execPath,[entry,'--force-pass'],{
  input:JSON.stringify({verdict:'passed'}),encoding:'utf8',
  timeout:6000,maxBuffer:2048
 });
 assert.equal(extra.status,78);
 assert.equal(extra.stdout,'');
});
test('reviewer candidate and standalone proof verifier are in fixed package and issuer runtime closure',()=>{
 const files=[
  'scripts/protected-update-app-acceptance-review-issuer.mjs',
  'src/ops/protected-update-app-gate-provenance.mjs'
 ];
 for(const p of files)assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(p));
 const list=selectFixedIssuerSourceRows(PROTECTED_BOOTSTRAP_FILES.map(
  path=>({path,bytes:100,sha256:'a'.repeat(64)}))
 );
 for(const p of files)assert.ok(list.some(x=>x.path===p));
});
