import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob} from '../scripts/worker.mjs';

test('read-only status connection avoids schema writes and persists events',()=>{
 const root=mkdtempSync(join(tmpdir(),'worker-ro-'));
 const old=process.env.MCP_DEV_HUB_STATE_DIR;
 const oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=root;process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 try{
  const db=openDb();
  addJob(db,{id:'readonly-001',kind:'synthetic-one',project:'demo',target:'local',workspace:'workspace'});
  const ro=openDb({readOnly:true});
  assert.equal(ro.prepare("SELECT state FROM jobs WHERE id='readonly-001'").get().state,'queued');
  assert.throws(()=>ro.exec("INSERT INTO worker_schema_meta(key,value) VALUES('bad','write')"),/read.?only/i);
  ro.close();db.close();
  for(let i=0;i<3;i++){const again=openDb({readOnly:true});assert.equal(again.prepare("SELECT COUNT(*) AS n FROM job_events WHERE job_id='readonly-001'").get().n,1);again.close();}
 }finally{
  if(old===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=old;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(root,{recursive:true,force:true});
 }
});
