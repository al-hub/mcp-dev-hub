import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,symlinkSync,rmSync,readFileSync,existsSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {sandboxArgs,resourceScopeArgs,validateScope,verifiedTapSummary,materializeSnapshot} from '../scripts/trusted-repo-check.mjs';
import {trustedRepoCheckRunner,canStartAiDevelopment} from '../scripts/worker.mjs';

function git(cwd,...args){
 const r=spawnSync('/usr/bin/git',args,{cwd,encoding:'utf8',env:{
  PATH:'/usr/bin:/bin',GIT_CONFIG_NOSYSTEM:'1',GIT_CONFIG_GLOBAL:'/dev/null',
  GIT_AUTHOR_NAME:'Synthetic',GIT_AUTHOR_EMAIL:'synthetic@example.invalid',
  GIT_COMMITTER_NAME:'Synthetic',GIT_COMMITTER_EMAIL:'synthetic@example.invalid'
 }});
 assert.equal(r.status,0,'synthetic Git fixture setup');
 return r.stdout.trim();
}
function fixture(fn){
 const root=mkdtempSync('/tmp/mcp-dev-hub-sandbox-test-');
 const worktree=join(root,'task');
 try{
  mkdirSync(worktree);
  git(worktree,'init','-q');
  mkdirSync(join(worktree,'tests'));
  writeFileSync(join(worktree,'tests','check.test.mjs'),
    "import test from 'node:test'; test('ok',()=>{});\n");
  git(worktree,'add','tests/check.test.mjs');
  git(worktree,'commit','-qm','synthetic test');
  return fn({root,worktree,repoDir:worktree,head:git(worktree,'rev-parse','HEAD')});
 }finally{rmSync(root,{recursive:true,force:true});}
}
function snapshot(ctx){
 const destination=mkdtempSync(join(ctx.root,'snapshot-'));
 const outcome=materializeSnapshot({repoDir:ctx.repoDir,head:ctx.head,destination});
 return {destination,...outcome};
}
test('sandbox binds a private pinned snapshot, not a mutable checkout',()=>{
 const args=sandboxArgs({
  snapshot:'/synthetic/snapshot',hosts:'/tmp/synthetic-hosts',
  testFiles:['tests/check.test.mjs']
 });
 assert.deepEqual(args.slice(0,3),['--clearenv','--unshare-all','--die-with-parent']);
 assert.equal(args.includes('--share-net'),false);
 assert.equal(args.includes('--bind'),false);
 assert.ok(args.includes('--tmpfs'));
 assert.ok(args.includes('/synthetic/snapshot'));
 assert.ok(!args.includes('/synthetic/root/task'));
 assert.ok(args.includes('/sandbox-home'));
 assert.equal(args.some(x=>x.startsWith('/home/')),false);
 assert.deepEqual(args.slice(-5),['--','/usr/bin/node','--test','--test-reporter=tap','tests/check.test.mjs']);
 assert.equal(args.filter(x=>x==='--ro-bind').length,6);
});
test('exact Git blob snapshot ignores dirty worktree and untracked private files',()=>fixture(ctx=>{
 assert.equal(validateScope(ctx).head,ctx.head);
 const original=readFileSync(join(ctx.worktree,'tests','check.test.mjs'),'utf8');
 writeFileSync(join(ctx.worktree,'tests','check.test.mjs'),'tampered after commit');
 writeFileSync(join(ctx.worktree,'ignored.private'),'synthetic forbidden');
 git(ctx.worktree,'update-index','--skip-worktree','tests/check.test.mjs');
 const result=snapshot(ctx);
 assert.deepEqual(result.testFiles,['tests/check.test.mjs']);
 assert.equal(readFileSync(join(result.destination,'tests','check.test.mjs'),'utf8'),original);
 assert.equal(existsSync(join(result.destination,'ignored.private')),false);
}));
test('stale HEAD, out-of-scope worktree and symlinked roots fail closed',()=>fixture(ctx=>{
 assert.throws(()=>validateScope({...ctx,head:'b'.repeat(40)}),/git_object_unavailable/);
 assert.throws(()=>validateScope({...ctx,root:ctx.worktree}),/outside_approved_root/);
 const alias=join(ctx.root,'alias');
 symlinkSync(ctx.worktree,alias);
 assert.throws(()=>validateScope({...ctx,worktree:alias}),/symlinked_path/);
 assert.throws(()=>validateScope({...ctx,head:'not-a-sha'}),/invalid_head/);
}));
test('committed symlink test source is never materialized',()=>fixture(ctx=>{
 symlinkSync('check.test.mjs',join(ctx.worktree,'tests','link.test.mjs'));
 git(ctx.worktree,'add','tests/link.test.mjs');
 git(ctx.worktree,'commit','-qm','synthetic symlink');
 const destination=mkdtempSync(join(ctx.root,'snapshot-'));
 assert.throws(()=>materializeSnapshot({repoDir:ctx.repoDir,
  head:git(ctx.worktree,'rev-parse','HEAD'),destination}),/unsafe_tree_entry/);
}));
test('final TAP epilogue, not a nested or partial summary, controls the verdict',()=>{
 const earlier='# tests 2\n# pass 2\n# fail 0\n';
 const final='1..130\n# tests 130\n# suites 0\n# pass 130\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1200\n';
 assert.equal(verifiedTapSummary(earlier+final,20),130);
 assert.equal(verifiedTapSummary(earlier,20),null);
 assert.equal(verifiedTapSummary(final.replace('# fail 0','# fail 1'),20),null);
 assert.equal(verifiedTapSummary(final.replace('# skipped 0','# skipped 1'),20),null);
 assert.equal(verifiedTapSummary(final.replace('# tests 130','# tests 10'),20),null);
});
test('Worker still refuses AI writes and an absent trusted check launcher',()=>{
 assert.equal(canStartAiDevelopment(),false);
 assert.equal(trustedRepoCheckRunner({executionDir:process.cwd(),baseSha:'a'.repeat(40)}),null);
});

test('untrusted code runs inside a resource-bounded user scope',()=>{
 const args=resourceScopeArgs({snapshot:'/synthetic/snapshot',
   hosts:'/tmp/synthetic-hosts',testFiles:['tests/check.test.mjs']});
 assert.deepEqual(args.slice(0,4),['--user','--scope','--collect','--quiet']);
 for(const limit of ['MemoryMax=1G','TasksMax=64','CPUQuota=100%'])assert.ok(args.includes(limit));
 assert.ok(args.includes('/usr/bin/bwrap'));
 assert.ok(args.includes('--unshare-all'));
 assert.ok(!args.includes('--share-net'));
});
test('tampering with the named commit object fails before any test executes',()=>fixture(ctx=>{
 const object=join(ctx.repoDir,'.git','objects',ctx.head.slice(0,2),ctx.head.slice(2));
 chmodSync(object,0o600);
 writeFileSync(object,'corrupted synthetic object');
 assert.throws(()=>validateScope(ctx),/git_object_unavailable|git_object_hash_mismatch/);
}));
