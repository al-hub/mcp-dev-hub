import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,registerReviewJob,collectReviewResult} from '../scripts/worker.mjs';

test('review results require matching job id and are durably stored',()=>{
 const dir=mkdtempSync(join(tmpdir(),'review-result-'));
 const prevDir=process.env.MCP_DEV_HUB_STATE_DIR,prevScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try {
  const db=openDb();
  registerReviewJob(db,{id:'review-003',kind:'review-opencode',project:'demo',target:'local',workspace:'workspace'});
  assert.equal(collectReviewResult(db,'review-003'),false);
  const output=join(dir,'review-results');mkdirSync(output);
  const file=join(output,'review-003.json');
  writeFileSync(file,JSON.stringify({jobId:'other-job',status:'completed',summary:'not ours'}));
  assert.equal(collectReviewResult(db,'review-003'),false);
  writeFileSync(file,JSON.stringify({jobId:'review-003',status:'completed',summary:'review findings'}));
  assert.equal(collectReviewResult(db,'review-003'),true);
  assert.deepEqual({...db.prepare('SELECT status,summary FROM review_results WHERE job_id=?').get('review-003')},{status:'completed',summary:'review findings'});
  db.close();
  const reopened=openDb();
  assert.equal(reopened.prepare('SELECT status FROM review_results').get().status,'completed');
  reopened.close();
 }finally{
  if(prevDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=prevDir;
  if(prevScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=prevScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
