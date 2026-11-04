import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,mkdirSync,writeFileSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {allocateWorktree} from '../src/jobs/worktree-allocate.mjs';
import {cleanupWorktree} from '../src/jobs/worktree-cleanup.mjs';
const git=(cwd,...args)=>{
 const r=spawnSync('git',args,{cwd,encoding:'utf8'});
 assert.equal(r.status,0,`git ${args.join(' ')}: ${r.stderr}`);
 return r.stdout.trim();
};
test('real git: allocate, preserve dirty files, then safely clean up',()=>{
 const top=mkdtempSync(join(tmpdir(),'mcp-wt-real-')),repo=join(top,'repo'),root=join(top,'managed');
 mkdirSync(repo);mkdirSync(root);
 const db=new DatabaseSync(':memory:');
 try {
  git(repo,'init','-q');
  git(repo,'config','user.email','ci@example.invalid');
  git(repo,'config','user.name','CI Tester');
  writeFileSync(join(repo,'README.md'),'initial\n');
  git(repo,'add','README.md');git(repo,'commit','-qm','initial');
  const baseSha=git(repo,'rev-parse','HEAD');
  const allocated=allocateWorktree(db,{taskId:'test-real-101',root,repoDir:repo,baseSha,branch:'task/test-real-101'});
  assert.equal(existsSync(allocated.path),true);
  assert.equal(git(allocated.path,'rev-parse','HEAD'),baseSha);
  const opts={taskId:'test-real-101',root,repoDir:repo,taskTerminal:true,leaseAlive:false,resultsPreserved:true};
  assert.equal(cleanupWorktree(db,{...opts,leaseAlive:true}).state,'retained');
  writeFileSync(join(allocated.path,'uncommitted.txt'),'keep me');
  assert.equal(cleanupWorktree(db,opts).state,'recovery_required');
  assert.equal(existsSync(join(allocated.path,'uncommitted.txt')),true);
  // A separate, clean finished job must be removable with actual git.
  const second=allocateWorktree(db,{taskId:'test-real-102',root,repoDir:repo,baseSha,branch:'task/test-real-102'});
  const done={...opts,taskId:'test-real-102'};
  assert.equal(cleanupWorktree(db,done).state,'removed');
  assert.equal(existsSync(second.path),false);
  assert.equal(cleanupWorktree(db,done).removed,false);
 }finally{db.close();rmSync(top,{recursive:true,force:true});}
});
