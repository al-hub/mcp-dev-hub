import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {registerWorktree,cleanupWorktree} from '../src/jobs/worktree-cleanup.mjs';
test('cleanup requires terminal, preserved, idle and clean worktree',()=>{
 const root=mkdtempSync(join(tmpdir(),'managed-wt-')),p=join(root,'work-one');
 mkdirSync(p);const db=new DatabaseSync(':memory:');
 try{
  registerWorktree(db,{taskId:'task-one',path:p,branch:'feature-one',root});
  let removed=0;
  const gitRunner=(args)=>{if(args[0]==='worktree'&&args[1]==='list')return {status:0,stdout:'worktree '+p+'\n'};if(args[0]==='status')return {status:0,stdout:''};if(args[0]==='worktree'&&args[1]==='remove'){removed++;return {status:0,stdout:''};}return {status:1,stdout:''};};
  const opts={taskId:'task-one',root,gitRunner,taskTerminal:true,leaseAlive:false,resultsPreserved:true};
  assert.equal(cleanupWorktree(db,{...opts,leaseAlive:true}).state,'retained');
  assert.equal(cleanupWorktree(db,{...opts,resultsPreserved:false}).state,'retained');
  assert.equal(cleanupWorktree(db,opts).state,'removed');
  assert.equal(cleanupWorktree(db,opts).removed,false);
  assert.equal(removed,1);
 }finally{db.close();rmSync(root,{recursive:true,force:true});}
});
test('dirty worktree is preserved for recovery',()=>{
 const root=mkdtempSync(join(tmpdir(),'managed-wt-')),p=join(root,'work-two');
 mkdirSync(p);const db=new DatabaseSync(':memory:');
 try{
  registerWorktree(db,{taskId:'task-two',path:p,branch:'feature-two',root});
  let removeCalls=0;
  const gitRunner=(args)=>{if(args[1]==='list')return {status:0,stdout:'worktree '+p+'\n'};if(args[0]==='status')return {status:0,stdout:'?? new-file.txt\n'};removeCalls++;return {status:0,stdout:''};};
  assert.equal(cleanupWorktree(db,{taskId:'task-two',root,taskTerminal:true,leaseAlive:false,resultsPreserved:true,gitRunner}).state,'recovery_required');
  assert.equal(removeCalls,0);
 }finally{db.close();rmSync(root,{recursive:true,force:true});}
});
