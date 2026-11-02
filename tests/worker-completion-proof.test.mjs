import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob,reconcile} from '../scripts/worker.mjs';

test('durable completion proof reconciles after DB restart and rejects wrong nonce',()=>{
 const dir=mkdtempSync(join(tmpdir(),'proof-')); const prior=process.env.MCP_DEV_HUB_STATE_DIR; const priorScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir; process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try{
  const db=openDb();
  addJob(db,{id:'proof-test-1',kind:'synthetic-one',project:'demo',target:'local',workspace:'workspace'});
  db.prepare("UPDATE jobs SET state='running',window='test-proof-dead' WHERE id='proof-test-1'").run();
  db.prepare('INSERT INTO job_run_nonces(job_id,attempt,nonce) VALUES(?,?,?)').run('proof-test-1',1,'a'.repeat(32));
  db.close();
  const d=join(dir,'run-proofs');mkdirSync(d);
  const p=join(d,'proof-test-1-attempt-1.txt');
  writeFileSync(p,'END proof-test-1 attempt=1 proof='+ 'b'.repeat(32)+' exit=0\n');
  const reopened=openDb();
  reconcile(reopened);
  assert.notEqual(reopened.prepare("SELECT state FROM jobs WHERE id='proof-test-1'").get().state,'succeeded');
  reopened.prepare("UPDATE jobs SET state='running' WHERE id='proof-test-1'").run();
  writeFileSync(p,'END proof-test-1 attempt=1 proof='+ 'a'.repeat(32)+' exit=0\n');
  reconcile(reopened);
  const record=reopened.prepare("SELECT state,exit_code FROM jobs WHERE id='proof-test-1'").get();
  assert.equal(record.state,'succeeded');assert.equal(record.exit_code,0);
  reconcile(reopened);assert.equal(reopened.prepare("SELECT COUNT(*) AS n FROM job_events WHERE job_id='proof-test-1' AND state='succeeded'").get().n,1);
  reopened.close();
 }finally{if(prior===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=prior;if(priorScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=priorScope;rmSync(dir,{recursive:true,force:true});}
});
