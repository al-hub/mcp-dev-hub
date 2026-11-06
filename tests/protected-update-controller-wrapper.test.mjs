import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';

test('candidate wrapper run from a checkout is denied with no root side effects',()=>{
  const entry=resolve('scripts/protected-update-controller-wrapper.mjs');
  const result=spawnSync(process.execPath,[entry],{
    encoding:'utf8',timeout:5000,env:{...process.env}
  });
  assert.equal(result.status,75);
  assert.equal(result.stdout,
    '{"state":"blocked","reason":"protected_entrypoint_guard"}\n');
  assert.equal(result.stderr,'');
});
test('candidate wrapper refuses user arguments before any child controller',()=>{
  const entry=resolve('scripts/protected-update-controller-wrapper.mjs');
  const result=spawnSync(process.execPath,[entry,'--arbitrary-command'],{
    encoding:'utf8',timeout:5000
  });
  assert.equal(result.status,75);
  assert.ok(!result.stdout.includes('secret'));
});
