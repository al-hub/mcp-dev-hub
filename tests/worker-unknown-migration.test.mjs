import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openDb,addJob,quarantineUnknownJob} from '../scripts/worker.mjs';
test('historic backfill happens only once even when event entries are later removed',()=>{
 const dir=mkdtempSync(join(tmpdir(),'backfill-once-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:staging';
 try{
  let db=openDb();addJob(db,{id:'test-backfill-1',kind:'synthetic-one',project:'demo',target:'local',workspace:'staging'});
  db.exec("DELETE FROM job_events WHERE job_id='test-backfill-1'");db.close();
  db=openDb();
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM job_events WHERE job_id='test-backfill-1'").get().n,0);
  db.close();
 }finally{if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;rmSync(dir,{recursive:true,force:true});}
});
test('unknown task quarantine requires explicit evidence and no live window',()=>{
 const dir=mkdtempSync(join(tmpdir(),'unknown-hold-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:staging';
 try{
  const db=openDb();addJob(db,{id:'test-unknown-1',kind:'synthetic-one',project:'demo',target:'local',workspace:'staging'});
  db.exec("UPDATE jobs SET state='unknown' WHERE id='test-unknown-1'");
  assert.throws(()=>quarantineUnknownJob(db,{id:'test-unknown-1',confirmedNoLiveProcess:true}),/evidence/);
  assert.equal(quarantineUnknownJob(db,{id:'test-unknown-1',confirmedNoLiveProcess:true,evidenceId:'verified-missing-window'}),true);
  assert.equal(db.prepare("SELECT state FROM jobs WHERE id='test-unknown-1'").get().state,'blocked');db.close();
 }finally{if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;rmSync(dir,{recursive:true,force:true});}
});