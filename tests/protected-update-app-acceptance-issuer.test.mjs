import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {issueFixedIndependentAppAcceptanceApproval,
 verifyUnchangedPhysicalOriginal}
 from '../scripts/protected-update-app-acceptance-approval-issuer.mjs';
import {APP_ACCEPTANCE_DOMAIN,assertFixedAppApprovalSigningScope}
 from '../src/ops/protected-update-app-acceptance.mjs';
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

test('large legitimate App packet allowed only for literal protected approver',()=>{
 const fixed='/usr/local/lib/mcp-dev-hub/protected-issuer/code/'+
   'scripts/protected-update-app-acceptance-approval-issuer.mjs';
 const ok={role:'approval',domain:APP_ACCEPTANCE_DOMAIN,
   json:'a'.repeat(11000),entryPath:fixed,argvLength:2};
 assert.equal(assertFixedAppApprovalSigningScope(ok),true);
 for(const changed of [
  {role:'reviewer'}, {domain:'mcp-dev-hub/protected-update-approval/v1\\n'},
  {entryPath:'/tmp/fake'}, {argvLength:3}, {json:''},
  {json:'a'.repeat(12001)}, {json:'🙂'.repeat(3001)}
 ]){
  assert.throws(()=>assertFixedAppApprovalSigningScope({...ok,...changed}),
    /independent_app_acceptance_denied/);
 }
});

test('exact unchanged original identities required after network round-trip',()=>{
 const prior=[
  {name:'ai-github-canary-policy.mjs',bytes:200,sha256:'a'.repeat(64),
   device:100,inode:20,mtimeMs:1000},
  {name:'ai-github-canary.mjs',bytes:210,sha256:'b'.repeat(64),
   device:100,inode:21,mtimeMs:1000}
 ];
 const guard=verifyUnchangedPhysicalOriginal;
 assert.equal(guard(prior,prior.map(f=>({...f}))),true);
 for(const [index,field,value] of [
  [0,'sha256','c'.repeat(64)],
  [0,'device',101],
  [0,'inode',90],
  [0,'mtimeMs',1001],
  [0,'bytes',201],
  [1,'name','ai-github-canary-policy.mjs'],
  [1,'sha256','bad'],
  [1,'inode',0],
  [1,'mtimeMs',NaN]
 ]){
  const changed=prior.map(f=>({...f}));
  changed[index][field]=value;
  assert.throws(()=>guard(prior,changed),
   /protected_app_acceptance_issuer_denied/);
 }
 for(const altered of [
  null,[],[prior[0]],
  [...prior,prior[0]],prior.slice().reverse(),
  [{...prior[0],bytes:-1},prior[1]]
 ])assert.throws(()=>guard(prior,altered),
  /protected_app_acceptance_issuer_denied/);
});
test('approval issuer inspects originals again AFTER live evidence before signing',()=>{
 const source=readFileSync(new URL(
  '../scripts/protected-update-app-acceptance-approval-issuer.mjs',
  import.meta.url),'utf8');
 const second=source.indexOf(
  'verifyUnchangedPhysicalOriginal(originals,physicalOriginal());');
 const proof=source.indexOf('const [gh,baseline]=await Promise.all(');
 const signing=source.indexOf('const signatureBase64=signFixedRolePayload({');
 assert.ok(proof>0 && second>proof && signing>second);
});
