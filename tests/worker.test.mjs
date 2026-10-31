import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob,jobs,ALLOWED,publicEvents,reconcile,tick} from '../scripts/worker.mjs';

test('durable queue accepts only approved fixed tasks and rejects duplicate IDs',()=>{
 const dir=mkdtempSync(join(tmpdir(),'worker-test-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try{
  const db=openDb();
  const job={id:'job-001',kind:'synthetic-one',project:'demo',target:'local',workspace:'workspace'};
  addJob(db,job);
  assert.equal(jobs(db)[0].state,'queued');
  assert.equal(publicEvents(db)[0].state,'queued');
  assert.equal(publicEvents(db,'demo').length,1);
  assert.equal(publicEvents(db,'other').length,0);
  assert.throws(()=>publicEvents(db,'../other'),/invalid project/);
  assert.equal(Object.hasOwn(publicEvents(db)[0],'workspace'),false);
  assert.equal(Object.hasOwn(publicEvents(db)[0],'target'),false);
  assert.throws(()=>addJob(db,job));
  assert.throws(()=>addJob(db,{...job,id:'job-002',kind:'shell'}));
  assert.throws(()=>addJob(db,{...job,id:'job-003',target:'remote'}));
  db.close();
  const reopened=openDb();
  assert.equal(jobs(reopened).length,1);
  reopened.close();
 }finally{
  if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
test('command allowlist is closed',()=>assert.deepEqual(Object.keys(ALLOWED).sort(),['repo-check','synthetic-one','synthetic-two']));

test('missing tmux evidence becomes unknown and prevents queued replay',()=>{
 const dir=mkdtempSync(join(tmpdir(),'worker-unknown-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try {
  const db=openDb();
  addJob(db,{id:'missing-one',kind:'synthetic-one',project:'demo',target:'local',workspace:'workspace'});
  addJob(db,{id:'waiting-two',kind:'synthetic-two',project:'demo',target:'local',workspace:'workspace'});
  db.prepare('UPDATE jobs SET state=?,window=? WHERE id=?').run('running','nonexistent-window-for-test','missing-one');
  reconcile(db);
  assert.equal(jobs(db)[0].state,'unknown');
  assert.equal(jobs(db)[1].state,'queued');
  assert.equal(tick(db),false);
  assert.equal(jobs(db)[1].state,'queued');
  db.close();
 } finally {
  if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
