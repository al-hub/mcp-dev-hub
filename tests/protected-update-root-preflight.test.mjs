import test from 'node:test';
import assert from 'node:assert/strict';
import {preflightRootProtectedUpdateRequest}
  from '../src/ops/protected-update-root-preflight.mjs';
test('fixed root preflight denies malformed request before credential access',async()=>{
  for(const raw of [
    '', '{}', '{"command":"sudo"}',
    '{"version":1,"version":1}',
    JSON.stringify({version:1,root:'/etc'})
  ]) await assert.rejects(preflightRootProtectedUpdateRequest(raw));
});
test('preflight is data-only: root implementation exports no installer action',async()=>{
  const module=await import('../src/ops/protected-update-root-preflight.mjs');
  assert.deepEqual(Object.keys(module),['preflightRootProtectedUpdateRequest']);
});
