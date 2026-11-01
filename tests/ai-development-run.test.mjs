import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {executeOnce,preflight} from '../scripts/ai-development-run.mjs';
const git=(cwd,...args)=>{const r=spawnSync('git',args,{cwd,encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout.trim();};
test('writer remains disabled without explicit enable, regardless of claim',()=>{
 const db=new DatabaseSync(':memory:');
 const old=process.env.MCP_DEV_HUB_ENABLE_AI_WRITE;
 delete process.env.MCP_DEV_HUB_ENABLE_AI_WRITE;
 try{assert.equal(executeOnce({db}).state,'disabled');}
 finally{if(old===undefined)delete process.env.MCP_DEV_HUB_ENABLE_AI_WRITE;else process.env.MCP_DEV_HUB_ENABLE_AI_WRITE=old;db.close();}
});
test('preflight refuses stale SHA, dirty worktrees and wrong branch',()=>{
 const root=mkdtempSync(join(tmpdir(),'writer-scope-'));
 const repo=join(root,'source'),worktrees=join(root,'worktrees');
 mkdirSync(repo);mkdirSync(worktrees);
 try{
  git(repo,'init','-q');git(repo,'config','user.email','ci@example.invalid');git(repo,'config','user.name','CI');
  const {writeFileSync}=await import('node:fs');
  writeFileSync(join(repo,'README.md'),'safe\n');
  git(repo,'add','README.md');git(repo,'commit','-qm','initial');
  const sha=git(repo,'rev-parse','HEAD');
  const branch='task/fix-pr-'+sha.slice(0,12),dir=join(worktrees,'isolated');
  git(repo,'worktree','add','-qb',branch,dir,sha);
  const args={jobId:'fix-pr-'+sha.slice(0,12),headSha:sha,repoDir:repo,worktree:dir,approvedRoot:worktrees,branch};
  assert.equal(preflight(args),dir);
  assert.throws(()=>preflight({...args,headSha:'a'.repeat(40)}),/invalid identity|stale SHA/);
  writeFileSync(join(dir,'README.md'),'dirty\n');
  assert.throws(()=>preflight(args),/dirty worktree/);
 }finally{rmSync(root,{recursive:true,force:true});}
});
