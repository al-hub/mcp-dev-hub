import test from 'node:test';
import assert from 'node:assert/strict';
import {
  readRootProtectedUpdateTrust,preflightAuthenticatedProtectedUpdate
} from '../src/ops/protected-update-root-evidence.mjs';

test('invalid operation fields fail before any root credential access',async()=>{
  for(const item of [
    {},
    {head:'a'.repeat(40)},
    {head:'a'.repeat(40),base:'a'.repeat(40)},
    {head:'a'.repeat(40),base:'b'.repeat(40),operationId:'../escape'},
    {head:'a'.repeat(40),base:'b'.repeat(40),
      operationId:'c'.repeat(32),prNumber:0}
  ]) await assert.rejects(preflightAuthenticatedProtectedUpdate(item),
    /protected_root_evidence_denied/);
});
test('root trust cannot be read by an ordinary test/Worker process',()=>{
  if(typeof process.geteuid!=='function'||process.geteuid()!==0){
    assert.throws(()=>readRootProtectedUpdateTrust(),
      /protected_root_evidence_denied/);
  }
  // When running an explicit root test, do not touch or print production
  // trust keys. Physical trust-root acceptance is a separate admin gate.
});
