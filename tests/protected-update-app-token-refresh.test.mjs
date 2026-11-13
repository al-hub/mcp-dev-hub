import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {
 decideRefreshPhase
} from '../scripts/protected-update-app-token-refresh.mjs';
const codex={uid:900,gid:900};
const reviewer={uid:901,gid:901};
const approval={uid:902,gid:902};
test('bootstrap is allowed only when both signer roles are absent',()=>{
 assert.equal(decideRefreshPhase({codex,reviewer:null,approval:null}),
   'bootstrap');
 assert.throws(()=>decideRefreshPhase({codex,reviewer,approval:null}));
 assert.throws(()=>decideRefreshPhase({codex,reviewer:null,approval}));
});
test('routine requires three distinct OS principals and distinct gids',()=>{
 assert.equal(decideRefreshPhase({codex,reviewer,approval}),'routine');
 assert.throws(()=>decideRefreshPhase({
   codex,reviewer,approval:{uid:901,gid:902}
 }));
 assert.throws(()=>decideRefreshPhase({
   codex,reviewer,approval:{uid:902,gid:900}
 }));
 assert.throws(()=>decideRefreshPhase({
   codex:null,reviewer,approval
 }));
});
test('checkout invocation cannot execute privileged refresh or issue secrets',()=>{
 const child=spawnSync(process.execPath,[
  'scripts/protected-update-app-token-refresh.mjs'
 ],{encoding:'utf8',timeout:10000,env:{
   PATH:'/usr/bin:/bin',HOME:'/nonexistent'
 },maxBuffer:4096});
 assert.equal(child.status,1);
 assert.equal(child.stdout,'');
 assert.match(child.stderr,/protected_app_token_refresh_denied_or_unknown/);
});
