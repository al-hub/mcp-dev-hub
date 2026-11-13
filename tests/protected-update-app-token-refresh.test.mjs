import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {
 decideRefreshPhase,assertUnchangedRefreshState
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
test('issuer provisioning and root refresh hold the same exclusive fence',()=>{
 const refresh=readFileSync('scripts/protected-update-app-token-refresh.mjs','utf8');
 const issuer=readFileSync('scripts/protected-update-issuer-provision.mjs','utf8');
 assert.match(refresh,/\.readonly-token-refresh\.lock/);
 assert.match(issuer,/\.readonly-token-refresh\.lock/);
 assert.match(issuer,/mkdirSync\(TOKEN_REFRESH_FENCE/);
 assert.match(issuer,/rmdirSync\(TOKEN_REFRESH_FENCE/);
});
test('locked refresh rejects changed phase, mint state or signer identity',()=>{
 const bootstrap={codex,reviewer:null,approval:null,phase:'bootstrap',
  firstMint:true};
 const routine={codex,reviewer,approval,phase:'routine',firstMint:false};
 for(const [before,current] of [
  [bootstrap,routine],
  [bootstrap,{...bootstrap,firstMint:false}],
  [bootstrap,{...bootstrap,codex:{...codex,gid:903}}],
  [routine,{...routine,reviewer:{...reviewer,uid:903}}],
  [routine,{...routine,approval:{...approval,gid:903}}]
 ])assert.throws(()=>assertUnchangedRefreshState(before,current),
  /protected_app_token_refresh_denied_or_unknown/);
 assert.doesNotThrow(()=>assertUnchangedRefreshState(routine,
  structuredClone(routine)));
});
test('refresh rechecks under the shared lock before the first token write',()=>{
 const source=readFileSync(new URL(
  '../scripts/protected-update-app-token-refresh.mjs',import.meta.url),'utf8');
 const body=source.split('export async function refreshPinnedAppReadOnlyTokens(){')[1];
 const expected=['const before=readRefreshState()',
  'mkdirSync(LOCK,{mode:0o700})','current=readRefreshState()',
  'assertUnchangedRefreshState(before,current)',
  'rmdirSync(LOCK);sync(TRUST);\n  throw e;',
  'const {reviewer,approval,phase,firstMint}=current',
  'staged(TRUST+'];
 let previous=-1;
 for(const step of expected){
  const next=body.indexOf(step);
  assert.ok(next>previous,step);
  previous=next;
 }
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
