import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {allocateWorktree,listManagedWorktrees} from '../src/jobs/worktree-allocate.mjs';
test('allocates unique registered worktree and rejects duplicates',()=>{
 const root=mkdtempSync(join(tmpdir(),'wt-root-')),repo=mkdtempSync(join(tmpdir(),'wt-repo-'));
 const db=new DatabaseSync(':memory:');
 try {
  const gitRunner=(args)=>{mkdirSync(args[4]);return {status:0,stdout:''};};
  const args={taskId:'task-101',root,repoDir:repo,baseSha:'a'.repeat(40),branch:'task/task-101',gitRunner};
  assert.equal(allocateWorktree(db,args).state,'active');
  assert.equal(listManagedWorktrees(db).length,1);
  assert.throws(()=>allocateWorktree(db,args),/exists|registered/);
  assert.throws(()=>allocateWorktree(db,{...args,taskId:'../escape'}),/invalid/);
 }finally{db.close();rmSync(root,{recursive:true,force:true});rmSync(repo,{recursive:true,force:true});}
});
test('records failed git creation for manual reconciliation',()=>{
 const root=mkdtempSync(join(tmpdir(),'wt-root-')),repo=mkdtempSync(join(tmpdir(),'wt-repo-'));
 const db=new DatabaseSync(':memory:');
 try {
  assert.throws(()=>allocateWorktree(db,{taskId:'task-102',root,repoDir:repo,baseSha:'a'.repeat(40),branch:'task/task-102',gitRunner:()=>({status:1})}),/allocation uncertain/);
  assert.equal(listManagedWorktrees(db).length,1);
  assert.equal(listManagedWorktrees(db)[0].state,'recovery_required');
 }finally{db.close();rmSync(root,{recursive:true,force:true});rmSync(repo,{recursive:true,force:true});}
});
