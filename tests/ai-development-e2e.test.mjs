import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,chmodSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {DatabaseSync} from 'node:sqlite';
import {claimDevelopment} from '../src/jobs/ai-development-claims.mjs';
import {executeOnce} from '../scripts/ai-development-run.mjs';
const git=(cwd,...args)=>{const r=spawnSync('git',args,{cwd,encoding:'utf8'});assert.equal(r.status,0,'Git fixture operation failed');return r.stdout.trim();};

test('isolated AGY edit -> fake Codex approval -> real Git commit and task-branch push is one-shot',()=>{
 const root=mkdtempSync(join(tmpdir(),'ai-commit-e2e-'));
 const repo=join(root,'source'),worktrees=join(root,'worktrees'),bare=join(root,'remote.git'),bin=join(root,'bin');
 for(const p of [repo,worktrees,bin])mkdirSync(p);
 const previous={path:process.env.PATH,write:process.env.MCP_DEV_HUB_ENABLE_AI_WRITE,push:process.env.MCP_DEV_HUB_ENABLE_AI_PUSH};
 const exe=(name,body)=>{const p=join(bin,name);writeFileSync(p,'#!/bin/sh\nset -eu\n'+body+'\n',{mode:0o700});chmodSync(p,0o700);return p;};
 try{
  git(root,'init','--bare','-q',bare);
  git(repo,'init','-q');
  git(repo,'config','user.name','Test Runner');git(repo,'config','user.email','ci@example.invalid');
  mkdirSync(join(repo,'tests'));
  writeFileSync(join(repo,'tests','example.test.mjs'),'export const value=1;\n');
  git(repo,'add','tests/example.test.mjs');git(repo,'commit','-qm','init');
  git(repo,'remote','add','origin',bare);
  const headSha=git(repo,'rev-parse','HEAD');
  const jobId='fix-pr-'+headSha.slice(0,12),branch='task/'+jobId,worktree=join(worktrees,'job-'+jobId);
  git(repo,'worktree','add','-qb',branch,worktree,headSha);
  assert.equal(git(worktree,'rev-parse','HEAD'),headSha,'worktree must match requested SHA');
  const agy=exe('agy', "printf 'export const value=2;\\n' > tests/example.test.mjs");
  const verdict={verdict:'APPROVE',baseSha:headSha,files:['tests/example.test.mjs'],findings:[]};
  const codex=exe('codex',"printf '%s\\n' '"+JSON.stringify(verdict)+"'");
  const npmBin=exe('npm','exit 0');
  process.env.MCP_DEV_HUB_ENABLE_AI_WRITE='1';
  process.env.MCP_DEV_HUB_ENABLE_AI_PUSH='1';
  const db=new DatabaseSync(':memory:');
  claimDevelopment(db,{jobId,headSha});
  const args={db,jobId,headSha,repoDir:repo,worktree,approvedRoot:worktrees,branch,prompt:'fixture',agyBin:agy,codexBin:codex,npmBin,allowPush:true};
  assert.equal(git(worktree,'rev-parse','HEAD'),headSha,'fixture HEAD must remain pinned after claim');
  const result=executeOnce(args);
  assert.equal(result.state,'pushed_task_branch');
  assert.equal(db.prepare('SELECT phase FROM ai_development_claims WHERE job_id=?').get(jobId).phase,'pushed');
  assert.match(git(bare,'show','refs/heads/'+branch+':tests/example.test.mjs'),/value=2/);
  assert.equal(git(repo,'rev-parse','HEAD'),headSha);
  assert.equal(executeOnce(args).state,'not_claimed');
  db.close();
 }finally{
  process.env.PATH=previous.path;
  for(const [k,v] of [['MCP_DEV_HUB_ENABLE_AI_WRITE',previous.write],['MCP_DEV_HUB_ENABLE_AI_PUSH',previous.push]])if(v===undefined)delete process.env[k];else process.env[k]=v;
  rmSync(root,{recursive:true,force:true});
 }
});
