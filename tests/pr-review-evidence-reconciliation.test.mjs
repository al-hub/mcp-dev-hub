import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openDb,reconcilePrReviewEvidence,registerReviewJob} from '../scripts/worker.mjs';
import {trackPr,prNextAction,recordPrGate} from '../src/jobs/pr-automation.mjs';
test('AI review result is never mistaken for independent approval',()=>{
 const prev=process.env.MCP_DEV_HUB_STATE_DIR,scope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 const dir=mkdtempSync(join(tmpdir(),'pr-review-gate-'));
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:staging';
 try{
  const db=openDb(),sha='a'.repeat(40),prKey='al-hub/mcp-dev-hub#17',id='review-pr-'+sha.slice(0,12);
  trackPr(db,{prKey,headSha:sha});
  recordPrGate(db,{prKey,headSha:sha,gate:'ci',verdict:'passed',evidenceId:'test-ci-123'});
  registerReviewJob(db,{id,kind:'review-opencode',project:'demo',target:'local',workspace:'staging'});
  db.prepare("UPDATE jobs SET state='succeeded' WHERE id=?").run(id);
  db.prepare('INSERT INTO review_results(job_id,status,summary,recorded_at) VALUES(?,?,?,?)').run(id,'completed','findings','2026-10-31T00:00:00Z');
  assert.equal(reconcilePrReviewEvidence(db,{prKey}).state,'awaiting_independent_approval');
  assert.equal(prNextAction(db,{prKey,observedSha:sha}).gate,'independent_review');
  db.close();
 }finally{if(prev===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=prev;if(scope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=scope;rmSync(dir,{force:true,recursive:true});}
});