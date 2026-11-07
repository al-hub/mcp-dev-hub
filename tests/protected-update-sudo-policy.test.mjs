import test from 'node:test';
import assert from 'node:assert/strict';
import {renderFixedProtectedSudoPolicy}
  from '../src/ops/protected-update-sudo-policy.mjs';

const denied=fn=>assert.throws(fn,/protected_sudo_policy_denied/);
test('least privilege grants exactly two root-owned commands',()=>{
  const p=renderFixedProtectedSudoPolicy({workerAccount:'synthetic_worker'});
  assert.equal(p.allowedCommands.length,2);
  assert.equal(p.mode,0o440);
  assert.equal(p.rootOwned,true);
  assert.equal(p.unrestrictedSudo,false);
  assert.equal(p.installAuthorized,false);
  assert.ok(p.allowedCommands.every(c=>c.startsWith('/usr/bin/node ')));
  assert.ok(p.allowedCommands.every(c=>!c.includes('*')));
  assert.ok(!p.text.includes('NOPASSWD:ALL'));
  assert.ok(!p.text.includes('/bin/sh'));
  assert.match(p.text,/env_reset/);
  assert.match(p.text,/!setenv/);
  assert.match(p.text,/NODE_OPTIONS/);
  assert.equal(p.text.match(/NOPASSWD:/g).length,1);
});
test('cannot inject arbitrary sudoers grammar through account name',()=>{
  for(const bad of [
    'root','sudo','issuer-reviewer','',null,'hello world',
    'test ALL=(ALL)', 'safe,ALL','safe\nroot ALL=(ALL) NOPASSWD:ALL',
    'safe#comment','a'.repeat(42),'-admin','issuer-approval'
  ])denied(()=>renderFixedProtectedSudoPolicy({workerAccount:bad}));
});
test('sudoers paths are fixed; no callers can customize root commands',()=>{
  const a=renderFixedProtectedSudoPolicy({workerAccount:'worker_1'});
  const b=renderFixedProtectedSudoPolicy({
    workerAccount:'worker_1',
    scripts:['/usr/bin/bash'],root:'/tmp',allowAll:true
  });
  assert.equal(a.text,b.text);
});
