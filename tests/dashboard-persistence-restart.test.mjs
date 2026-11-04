import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob} from '../scripts/worker.mjs';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';

test('SSE resumes after dashboard and SQLite reopen without repeating acknowledged events',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'replay-test-'));
 const previousDir=process.env.MCP_DEV_HUB_STATE_DIR;
 const previousScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='alpha:local:workspace';
 const token='x'.repeat(32);
 const headers={Authorization:'Bearer '+token};
 let db,server;
 const close=async()=>{if(server){await new Promise(resolve=>server.close(resolve));server=null;}if(db){db.close();db=null;}};
 async function connect(lastId){
  const app=createReadOnlyDashboard({token,project:'alpha',repository:'example/app',db,readGithub:async()=>({})});
  server=app.server;
  const address=await app.listen();
  const response=await fetch('http://localhost:'+address.port+'/api/stream',{headers:lastId===undefined?headers:{...headers,'Last-Event-ID':String(lastId)}});
  const reader=response.body.getReader();
  const chunk=await reader.read();
  const frame=new TextDecoder().decode(chunk.value);
  await reader.cancel();
  return frame;
 }
 try {
  db=openDb();
  addJob(db,{id:'job-alpha',kind:'synthetic-one',project:'alpha',target:'local',workspace:'workspace'});
  const first=await connect();
  assert.match(first,/"state":"queued"/);
  const firstId=Number(first.match(/id: ([0-9]+)/)[1]);
  await close();
  db=openDb();
  db.prepare('UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=?').run('succeeded',0,new Date().toISOString(),'job-alpha');
  const resumed=await connect(firstId);
  assert.match(resumed,/"state":"succeeded"/);
  assert.doesNotMatch(resumed,/"state":"queued"/);
  assert.ok(Number(resumed.match(/id: ([0-9]+)/)[1])>firstId);
 }finally{
  await close();
  if(previousDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=previousDir;
  if(previousScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=previousScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
