import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob} from '../scripts/worker.mjs';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';

test('SSE Last-Event-ID isolates project stream across interleaved global SQLite job_events and reopen',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'sse-global-cursor-'));
 const previousDir=process.env.MCP_DEV_HUB_STATE_DIR;
 const previousScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 const token='x'.repeat(32);
 const headers={Authorization:'Bearer '+token};
 let db,server;
 const close=async()=>{
  if(server){await new Promise(resolve=>server.close(resolve));server=null;}
  if(db){db.close();db=null;}
 };
 async function readStreamFrame(lastId){
  const app=createReadOnlyDashboard({token,project:'alpha',repository:'example/app',db,readGithub:async()=>({repository:'example/app',issues:[]})});
  server=app.server;
  const address=await app.listen();
  const requestHeaders=lastId===undefined?headers:{...headers,'Last-Event-ID':String(lastId)};
  const response=await fetch('http://localhost:'+address.port+'/api/stream',{headers:requestHeaders,signal:AbortSignal.timeout(5000)});
  assert.equal(response.status,200);
  const reader=response.body.getReader();
  try{
   const chunk=await reader.read();
   return new TextDecoder().decode(chunk.value);
  }finally{
   await reader.cancel();
   await close();
  }
 }
 try{
  db=openDb();
  process.env.MCP_DEV_HUB_APPROVED_SCOPE='alpha:local:workspace';
  addJob(db,{id:'job-alpha',kind:'synthetic-one',project:'alpha',target:'local',workspace:'workspace'});
  const firstFrame=await readStreamFrame();
  assert.match(firstFrame,/"jobId":"job-alpha"/);
  assert.match(firstFrame,/"state":"queued"/);
  assert.doesNotMatch(firstFrame,/job-beta|"project":"beta"/);
  const firstAlphaId=Number(firstFrame.match(/id: ([0-9]+)/)[1]);

  db=openDb();
  process.env.MCP_DEV_HUB_APPROVED_SCOPE='beta:local:workspace';
  addJob(db,{id:'job-beta',kind:'synthetic-two',project:'beta',target:'local',workspace:'workspace'});
  const betaEventId=Number(db.prepare('SELECT id FROM job_events WHERE project=?').get('beta').id);
  assert.ok(betaEventId>firstAlphaId);

  db.prepare('UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=?').run('succeeded',0,new Date().toISOString(),'job-alpha');
  const secondAlphaRow=db.prepare('SELECT id FROM job_events WHERE project=? AND id>?').get('alpha',firstAlphaId);
  const secondAlphaId=Number(secondAlphaRow.id);
  assert.ok(secondAlphaId>betaEventId);

  const beforeRestartFrame=await readStreamFrame(firstAlphaId);
  assert.match(beforeRestartFrame,new RegExp('id: '+secondAlphaId+'\\b'));
  assert.match(beforeRestartFrame,/"jobId":"job-alpha"/);
  assert.match(beforeRestartFrame,/"state":"succeeded"/);
  assert.doesNotMatch(beforeRestartFrame,/job-beta|"project":"beta"|"state":"queued"|event: reset/);

  db=openDb();
  const afterRestartFrame=await readStreamFrame(firstAlphaId);
  assert.match(afterRestartFrame,new RegExp('id: '+secondAlphaId+'\\b'));
  assert.match(afterRestartFrame,/"jobId":"job-alpha"/);
  assert.match(afterRestartFrame,/"state":"succeeded"/);
  assert.doesNotMatch(afterRestartFrame,/job-beta|"project":"beta"|"state":"queued"|event: reset/);
 }finally{
  await close();
  if(previousDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=previousDir;
  if(previousScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=previousScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
