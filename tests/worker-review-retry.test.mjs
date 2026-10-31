import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,registerReviewJob,recordReviewFailure,releaseDueReviewRetries,jobs} from '../scripts/worker.mjs';
test('review retry durable across restarts and bounded to three additional attempts',()=>{
 const dir=mkdtempSync(join(tmpdir(),'review-worker-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try {
  let db=openDb();
  registerReviewJob(db,{id:'review-001',kind:'cli-smoke',project:'demo',target:'local',workspace:'workspace'});
  assert.equal(db.prepare('SELECT attempt FROM review_attempts').get().attempt,1);
  const start=Date.parse('2026-10-31T00:00:00.000Z');
  for(let attempt=1;attempt<=4;attempt++){
   db.prepare("UPDATE jobs SET state='failed',exit_code=1 WHERE id='review-001'").run();
   const decision=recordReviewFailure(db,'review-001','timeout',{at:start+attempt*100000});
   if(attempt<=3){
    assert.equal(decision.retry,true);
    assert.equal(releaseDueReviewRetries(db,{at:start+attempt*100000}),0);
    db.close();db=openDb();
    assert.equal(db.prepare('SELECT attempt FROM review_attempts').get().attempt,attempt+1);
    assert.equal(releaseDueReviewRetries(db,{at:start+attempt*100000+90001}),1);
    assert.equal(jobs(db)[0].state,'queued');
    assert.equal(releaseDueReviewRetries(db,{at:start+attempt*100000+90001}),0);
   }else{assert.equal(decision.retry,false);assert.equal(jobs(db)[0].state,'blocked');}
  }
  assert.equal(db.prepare('SELECT count(*) AS n FROM review_attempt_log').get().n,4);
  db.close();
 }finally{
  if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
test('uncertain outcomes and nontransient failures never replay',()=>{
 const dir=mkdtempSync(join(tmpdir(),'review-worker-'));const a=process.env.MCP_DEV_HUB_STATE_DIR,b=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try{
  const db=openDb();registerReviewJob(db,{id:'review-002',kind:'cli-smoke',project:'demo',target:'local',workspace:'workspace'});
  db.prepare("UPDATE jobs SET state='failed'").run();
  assert.equal(recordReviewFailure(db,'review-002','timeout',{outcomeKnown:false}).state,'recovering');
  assert.equal(releaseDueReviewRetries(db),0);
  assert.equal(db.prepare('SELECT attempt FROM review_attempts').get().attempt,1);
  db.close();
 }finally{
  if(a===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=a;
  if(b===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=b;
  rmSync(dir,{recursive:true,force:true});
 }
});
