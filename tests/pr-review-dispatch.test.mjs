import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {openDb,enqueuePrReviewIfReady,reconcilePrReviewEvidence,registerReviewJob,claimPrDevelopmentIfNeeded,tick,jobs} from '../scripts/worker.mjs';
import {trackPr} from '../src/jobs/pr-automation.mjs';
test('PR reviewer dispatch is idempotent, scoped and pinned to exact SHA',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-review-dispatch-'));
 const old=Object.fromEntries(['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_WORKTREE_BASE_SHA','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO','MCP_DEV_HUB_AUTOMATION_PR_KEY','MCP_DEV_HUB_TRUSTED_RUNNER_ROOT'].map(k=>[k,process.env[k]]));
 const sha='a'.repeat(40);
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='example:local:staging';
 process.env.MCP_DEV_HUB_WORKTREE_BASE_SHA='b'.repeat(40);
 process.env.MCP_DEV_HUB_WORKTREE_ROOT=dir;
 process.env.MCP_DEV_HUB_WORKTREE_REPO=dir;
 process.env.MCP_DEV_HUB_TRUSTED_RUNNER_ROOT=process.cwd();
 process.env.MCP_DEV_HUB_AUTOMATION_PR_KEY='al-hub/mcp-dev-hub#17';
 try{
  const db=openDb();
  trackPr(db,{prKey:'al-hub/mcp-dev-hub#17',headSha:sha});
  assert.equal(enqueuePrReviewIfReady(db,{gate:'ci',state:'verifying',headSha:sha}),false);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'verifying',headSha:'b'.repeat(40)}),false);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'blocked',headSha:sha}),true);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'verifying',headSha:sha}),false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM jobs').get().n,1);
  assert.equal(db.prepare('SELECT attempt FROM review_attempts').get().attempt,1);
  delete process.env.MCP_DEV_HUB_TRUSTED_RUNNER_ROOT;
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'blocked',headSha:sha}),false);
  db.close();
 }finally{
  for(const [k,v] of Object.entries(old)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
test('Worker blocks review and PR jobs when trusted outside-PR runner is missing or inside untrusted PR worktree',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-runner-guard-'));
 const repo=join(dir,'repo'),worktrees=join(dir,'worktrees');
 mkdirSync(repo);mkdirSync(worktrees);
 const git=(cwd,...args)=>spawnSync('git',args,{cwd,encoding:'utf8'});
 git(repo,'init','-q');git(repo,'config','user.email','ci@example.invalid');git(repo,'config','user.name','CI');
 writeFileSync(join(repo,'README.md'),'init\n');git(repo,'add','README.md');git(repo,'commit','-qm','init');
 const sha=git(repo,'rev-parse','HEAD').stdout.trim();
 const keys=['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO','MCP_DEV_HUB_AUTOMATION_PR_KEY','MCP_DEV_HUB_TRUSTED_RUNNER_ROOT'];
 const saved=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
 Object.assign(process.env,{
  MCP_DEV_HUB_STATE_DIR:dir,MCP_DEV_HUB_APPROVED_SCOPE:'example:local:staging',
  MCP_DEV_HUB_WORKTREE_ROOT:worktrees,MCP_DEV_HUB_WORKTREE_REPO:repo,
  MCP_DEV_HUB_AUTOMATION_PR_KEY:'al-hub/mcp-dev-hub#17'
 });
 delete process.env.MCP_DEV_HUB_TRUSTED_RUNNER_ROOT;
 try{
  const db=openDb();
  trackPr(db,{prKey:'al-hub/mcp-dev-hub#17',headSha:sha});
  const id='review-pr-'+sha.slice(0,12);
  registerReviewJob(db,{id,kind:'review-opencode',project:'example',target:'local',workspace:'staging'});
  assert.equal(tick(db),false);
  assert.equal(jobs(db)[0].state,'blocked');
  // Also block if trusted runner points inside worktree root
  const id2='review-002';
  registerReviewJob(db,{id:id2,kind:'review-opencode',project:'example',target:'local',workspace:'staging'});
  process.env.MCP_DEV_HUB_TRUSTED_RUNNER_ROOT=worktrees;
  assert.equal(tick(db),false);
  assert.equal(db.prepare('SELECT state FROM jobs WHERE id=?').get(id2).state,'blocked');
  db.close();
 }finally{
  for(const [k,v] of Object.entries(saved)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
test('review findings require remediation and never substitute for independent approval',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-review-findings-'));
 const env=Object.fromEntries(['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_ENABLE_AI_WRITE','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO'].map(k=>[k,process.env[k]]));
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='example:local:staging';
 const prKey='al-hub/mcp-dev-hub#17',sha='c'.repeat(40),id='review-pr-'+sha.slice(0,12);
 try{
  const db=openDb();
  trackPr(db,{prKey,headSha:sha});
  registerReviewJob(db,{id,kind:'review-opencode',project:'example',target:'local',workspace:'staging'});
  db.prepare("UPDATE jobs SET state='succeeded',exit_code=0 WHERE id=?").run(id);
  db.prepare('INSERT INTO review_results(job_id,status,summary,recorded_at) VALUES(?,?,?,?)')
   .run(id,'completed','REVIEW_FINDINGS:\n1. Concrete defect in parser',new Date().toISOString());
  assert.equal(reconcilePrReviewEvidence(db,{prKey}).state,'remediation_required');
  assert.equal(claimPrDevelopmentIfNeeded(db,{prKey}).claimed,true);
  assert.equal(claimPrDevelopmentIfNeeded(db,{prKey}).claimed,false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM ai_development_claims').get().n,1);
  process.env.MCP_DEV_HUB_ENABLE_AI_WRITE='1';
  process.env.MCP_DEV_HUB_WORKTREE_ROOT=dir;
  process.env.MCP_DEV_HUB_WORKTREE_REPO=dir;
  assert.equal(claimPrDevelopmentIfNeeded(db,{prKey}).claimed,false);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE kind='ai-development'").get().n,1);
  assert.equal(claimPrDevelopmentIfNeeded(db,{prKey}).claimed,false);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM jobs WHERE kind='ai-development'").get().n,1);
  db.prepare('UPDATE review_results SET summary=? WHERE job_id=?').run('REVIEW_FINDINGS: no findings',id);
  assert.equal(reconcilePrReviewEvidence(db,{prKey}).state,'awaiting_independent_approval');
  db.close();
 }finally{
  for(const [k,v] of Object.entries(env)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
