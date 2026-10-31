import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openDb,enqueuePrReviewIfReady} from '../scripts/worker.mjs';
test('PR reviewer dispatch is idempotent, scoped and pinned to exact SHA',()=>{
 const dir=mkdtempSync(join(tmpdir(),'pr-review-dispatch-'));
 const old=Object.fromEntries(['MCP_DEV_HUB_STATE_DIR','MCP_DEV_HUB_APPROVED_SCOPE','MCP_DEV_HUB_WORKTREE_BASE_SHA','MCP_DEV_HUB_WORKTREE_ROOT','MCP_DEV_HUB_WORKTREE_REPO'].map(k=>[k,process.env[k]]));
 const sha='a'.repeat(40);
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='example:local:staging';
 process.env.MCP_DEV_HUB_WORKTREE_BASE_SHA='b'.repeat(40);
 process.env.MCP_DEV_HUB_WORKTREE_ROOT=dir;
 process.env.MCP_DEV_HUB_WORKTREE_REPO=dir;
 try{
  const db=openDb();
  assert.equal(enqueuePrReviewIfReady(db,{gate:'ci',state:'verifying',headSha:sha}),false);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'verifying',headSha:'b'.repeat(40)}),false);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'verifying',headSha:sha}),true);
  assert.equal(enqueuePrReviewIfReady(db,{gate:'independent_review',state:'verifying',headSha:sha}),false);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM jobs').get().n,1);
  assert.equal(db.prepare('SELECT attempt FROM review_attempts').get().attempt,1);
  db.close();
 }finally{
  for(const [k,v] of Object.entries(old)){if(v===undefined)delete process.env[k];else process.env[k]=v;}
  rmSync(dir,{recursive:true,force:true});
 }
});