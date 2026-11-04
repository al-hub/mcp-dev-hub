import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {openDb,addJob,reconcileStarting} from '../scripts/worker.mjs';

test('interrupted launch remains fail-closed instead of being automatically replayed',()=>{
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 const dir=mkdtempSync(join(tmpdir(),'mcp-start-'));
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='sample:local:staging';
 try{
  const db=openDb();
  addJob(db,{id:'job-launch-1',kind:'synthetic-one',project:'sample',target:'local',workspace:'staging'});
  db.prepare("UPDATE jobs SET state='starting',window='job-launch-1-a1',updated_at=? WHERE id='job-launch-1'").run(new Date(1000).toISOString());
  reconcileStarting(db,{at:50000});
  assert.equal(db.prepare("SELECT state FROM jobs WHERE id='job-launch-1'").get().state,'unknown');
  reconcileStarting(db,{at:60000});
  assert.equal(db.prepare("SELECT state FROM jobs WHERE id='job-launch-1'").get().state,'unknown');
  db.close();
 }finally{
  if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(dir,{recursive:true,force:true});
 }
});