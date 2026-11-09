import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {fixedRoutineOperationId,readFixedRoutineIssuerContext,
  readFixedRoutineCodexReceipt,readFixedRoutineReviewerHandoff}
  from '../src/ops/protected-update-issuer-runtime.mjs';
test('operation ID is exact 32 lowercase hex with no unscoped fallback',()=>{
 const id='a'.repeat(32);
 assert.equal(fixedRoutineOperationId(id),id);
 for(const invalid of [undefined,null,'','A'.repeat(32),
  'a'.repeat(31),'a'.repeat(33),'../'+'a'.repeat(29),
  'a'.repeat(32)+'/../','x'.repeat(32)]){
  assert.throws(()=>fixedRoutineOperationId(invalid),
   /protected_signer_runtime_denied/);
 }
});
test('checkout cannot read signer operation slots or Codex receipt',()=>{
 assert.throws(()=>readFixedRoutineIssuerContext());
 assert.throws(()=>readFixedRoutineCodexReceipt());
 assert.throws(()=>readFixedRoutineReviewerHandoff());
});
test('uninstalled routine role executables reject invocation with candidate operation ID',()=>{
 for(const name of [
  'protected-update-routine-review-issuer.mjs',
  'protected-update-routine-approval-issuer.mjs'
 ]){
  const path=fileURLToPath(new URL('../scripts/'+name,import.meta.url));
  const result=spawnSync(process.execPath,[path],{
   env:{PATH:process.env.PATH||'/usr/bin:/bin',
    MCP_PROTECTED_OPERATION_ID:'a'.repeat(32)},
   encoding:'utf8',timeout:5000,maxBuffer:1024
  });
  assert.equal(result.status,1);
  assert.equal(result.stdout,'');
 }
});
