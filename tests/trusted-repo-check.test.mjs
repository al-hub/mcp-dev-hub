import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {sandboxArgs,validateScope} from '../scripts/trusted-repo-check.mjs';

function git(cwd,...args){
 const r=spawnSync('/usr/bin/git',args,{cwd,encoding:'utf8',env:{
  PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',
  GIT_AUTHOR_NAME:'Synthetic',GIT_AUTHOR_EMAIL:'synthetic@example.invalid',
  GIT_COMMITTER_NAME:'Synthetic',GIT_COMMITTER_EMAIL:'synthetic@example.invalid'
 }});
 assert.equal(r.status,0,'synthetic git fixture setup');
 return r.stdout.trim();
}
function fixture(fn) {
 const root=mkdtempSync('/tmp/mcp-dev-hub-sandbox-test-');
 const worktree=join(root,'task');
 try {
  mkdirSync(worktree);
  git(worktree,'init','-q');
  mkdirSync(join(worktree,'tests'));
  writeFileSync(join(worktree,'tests','check.test.mjs'),"import test from 'node:test'; test('ok',()=>{});\n");
  git(worktree,'add','tests/check.test.mjs');
  git(worktree,'commit','-qm','synthetic test');
  return fn({root,worktree,head:git(worktree,'rev-parse','HEAD')});
 } finally{rmSync(root,{recursive:true,force:true});}
}
test('sandbox uses an isolated namespace and an immutable fixed test command',()=>{
 const args=sandboxArgs({
  worktree:'/synthetic/root/task',hosts:'/tmp/synthetic-hosts',
  testFiles:['tests/check.test.mjs']
 });
 assert.deepEqual(args.slice(0,3),['--clearenv','--unshare-all','--die-with-parent']);
 assert.ok(args.includes('--ro-bind'));
 assert.ok(args.includes('--tmpfs'));
 assert.ok(args.includes('/work'));
 assert.equal(args.includes('--share-net'),false);
 assert.equal(args.includes('--bind'),false);
 assert.equal(args.includes('/home/host'),false);
 assert.deepEqual(args.slice(-5),['--','/usr/bin/node','--test','--test-reporter=tap','tests/check.test.mjs']);
 assert.ok(!args.includes('/etc/passwd'));
 assert.equal(args.filter(x=>x==='--ro-bind').length,6);
});
test('clean exact synthetic worktree is accepted; dirty or stale HEAD is rejected',()=>fixture(ctx=>{
 assert.deepEqual(validateScope(ctx).testFiles,['tests/check.test.mjs']);
 assert.throws(()=>validateScope({...ctx,head:'b'.repeat(40)}),/head_changed/);
 writeFileSync(join(ctx.worktree,'tests','extra.test.mjs'),'not committed');
 assert.throws(()=>validateScope(ctx),/dirty_checkout/);
}));
test('outside approved scope and symlink worktrees fail closed',()=>fixture(ctx=>{
 assert.throws(()=>validateScope({...ctx,root:ctx.worktree}),/outside_approved_root/);
 const alias=join(ctx.root,'alias');
 symlinkSync(ctx.worktree,alias);
 assert.throws(()=>validateScope({...ctx,worktree:alias}),/symlinked_path/);
 assert.throws(()=>validateScope({...ctx,head:'not-a-sha'}),/invalid_head/);
}));
test('untrusted symlinked test file is rejected even if committed',()=>fixture(ctx=>{
 const file=join(ctx.worktree,'tests','link.test.mjs');
 symlinkSync('check.test.mjs',file);
 git(ctx.worktree,'add','tests/link.test.mjs');
 git(ctx.worktree,'commit','-qm','synthetic symlink');
 assert.throws(()=>validateScope({...ctx,head:git(ctx.worktree,'rev-parse','HEAD')}),/untrusted_test_file/);
}));
