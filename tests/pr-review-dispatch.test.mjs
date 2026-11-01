import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openDb,enqueuePrReviewIfReady,reconcilePrReviewEvidence,registerReviewJob} from '../scripts/worker.mjs';
import {trackPr} from '../src/jobs/pr-automation.mjs';
test('PR reviewer dispatch is idempotent, scoped and pinned to exact SHA',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-review-dispatch-'));
 const old=Object.fromEntries(['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_WORKTREE_BASE_SHA','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO','MCP_DEV_HUB_AUTOMATION_PR_KEY'].map(k=>[k,process.env[k]]));
 const sha='a'.repeat(40);
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='example:local:staging';
 process.env.MCP_DEV_HUB_WORKTREE_BASE_SHA='b'.repeat(40);
 process.env.MCP_DEV_HUB_WORKTREE_ROOT=dir;
 process.env.MCP_DEV_HUB_WORKTREE_REPO=dir;
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
  db.close();
 }finally{
  for(const [k,v] of Object.entries(old)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
test('review findings require remediation and never substitute for independent approval',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-review-findings-'));
 const env=Object.fromEntries(['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE'].map(k=>[k,process.env[k]]));
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='example:local:staging';
 const prKey='al-hub/mcp-dev-hub#17',sha='c'.repeat(40),id='review-pr-'+sha.slice(0,12);
 try{
  const db=openDb();
  trackPr(db,{prKey,headSha:sha});
  registerReviewJob(db,{id,kind:'review-opencode',project:'example',target:'local',workspace:'staging'});
  db.prepare("UPDATE jobs SET state='succeeded',exit_code=0 WHERE id=?").run(id);
  db.prepare('INSERT INTO review_results(job_id,status,summary,recorded_at) VALUES(?,?,?,?)')
   .run(id,'completed','REVIEW_FINDINGS:\\n1. Concrete defect in parser',new Date().toISOString());
  assert.equal(reconcilePrReviewEvidence(db,{prKey}).state,'remediation_required');
  db.prepare('UPDATE review_results SET summary=? WHERE job_id=?').run('REVIEW_FINDINGS: no findings',id);
  assert.equal(reconcilePrReviewEvidence(db,{prKey}).state,'awaiting_independent_approval');
  db.close();
 }finally{
  for(const [k,v] of Object.entries(env)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});
