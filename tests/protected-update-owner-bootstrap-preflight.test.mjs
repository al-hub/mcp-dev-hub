import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {
 evaluateOwnerBootstrapHandoff,
 inspectLocalOwnerBootstrapHandoff,PINNED_OWNER_ORIGINAL_FILES
} from '../scripts/protected-update-owner-bootstrap-preflight.mjs';
import {PROTECTED_BOOTSTRAP_FILES}
  from '../scripts/protected-update-bootstrap-pack.mjs';

const denied=fn=>assert.throws(fn,
 /protected_owner_bootstrap_preflight_denied/);
const good={head:'a'.repeat(40),expectedHead:'a'.repeat(40),
 manifestSha256:'b'.repeat(64),expectedManifestSha256:'b'.repeat(64),
 fileCount:62,baselineConfirmed:true,
 baselineCommit:'175ba1a481d9a55c0567402a2c905f457c7601e5',
 baselineFiles:PINNED_OWNER_ORIGINAL_FILES.map(x=>({...x}))};
test('verified packet and original check are NEVER owner/root authorization',()=>{
 const r=evaluateOwnerBootstrapHandoff(good);
 assert.equal(r.phase,'nonprivileged_owner_preflight_only');
 for(const k of ['ownerIdentityAuthenticated','signerProvenanceVerified',
  'independentGitHubApprovalVerified','privilegedInstallerApproved',
  'rootInstallAuthorized','operationalReviewReceiptIssued',
  'safeToMerge','safeToCloseIssue'])assert.equal(r[k],false);
});
test('wrong head, digest, original baseline, malformed input fail closed',()=>{
 for(const v of [
  {...good,head:'c'.repeat(40)},
  {...good,expectedHead:'0'},
  {...good,manifestSha256:'f'.repeat(64)},
  {...good,expectedManifestSha256:'not a hash'},
  {...good,fileCount:0},
  {...good,fileCount:1000},
  {...good,baselineConfirmed:false},
  {...good,baselineCommit:'c'.repeat(40)},
  {...good,baselineFiles:good.baselineFiles.map((x,i)=>i===0?{...x,sha256:'f'.repeat(64)}:x)},
  {...good,baselineFiles:good.baselineFiles.map((x,i)=>i===1?{...x,bytes:x.bytes+1}:x)},
  {...good,baselineFiles:good.baselineFiles.slice(1)},{},
 ])denied(()=>evaluateOwnerBootstrapHandoff(v));
});
test('owner preflight is read-only and may not be executed as root',()=>{
 const path=fileURLToPath(new URL(
  '../scripts/protected-update-owner-bootstrap-preflight.mjs',import.meta.url));
 const cli=spawnSync(process.execPath,[path],{
  encoding:'utf8',timeout:5000,maxBuffer:512
 });
 assert.equal(cli.status,1);
 assert.equal(cli.stdout,'');
 assert.match(cli.stderr,/protected_owner_bootstrap_preflight_denied/);
 denied(()=>inspectLocalOwnerBootstrapHandoff({
  repositoryPath:'/tmp/nonexistent',outputPath:'/tmp/nonexistent',
  baselineCommit:'a'.repeat(40),head:'a'.repeat(40),
  expectedManifestSha256:'b'.repeat(64)
 }));
 const src=readFileSync(path,'utf8');
 for(const bad of ['spawnSync(\'sudo\'','spawnSync(\'/usr/sbin/useradd\'',
  'process.setuid(','generateKeyPairSync','chmodSync(','writeFileSync('])
  assert.equal(src.includes(bad),false);
});
test('owner preflight is part of the frozen immutable review packet',()=>{
 assert.ok(PROTECTED_BOOTSTRAP_FILES.includes(
  'scripts/protected-update-owner-bootstrap-preflight.mjs'));
});
