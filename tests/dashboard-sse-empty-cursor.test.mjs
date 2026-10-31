import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';
test('SSE empty-project stale cursor resets and emits new events',async()=>{
 const db=new DatabaseSync(':memory:');
 db.exec('CREATE TABLE job_events (id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT,kind TEXT,project TEXT,state TEXT,exit_code INTEGER,created_at TEXT)');
 const token='synthetic-test-access-token-1234567';
 const app=createReadOnlyDashboard({token,project:'example',repository:'example/repo',db,readGithub:async()=>({})});
 try{
  const {port}=await app.listen();
  const response=await fetch('http://localhost:'+port+'/api/stream',{headers:{Authorization:'Bearer '+token,'Last-Event-ID':'2147483647'},signal:AbortSignal.timeout(4000)});
  assert.equal(response.status,200);
  const reader=response.body.getReader();let all='';
  for(let i=0;i<3&&!all.includes('event: reset');i++){const part=await reader.read();all+=new TextDecoder().decode(part.value);}
  assert.match(all,/event: reset/);
  await reader.cancel();
 }finally{await new Promise(resolve=>app.server.close(resolve));db.close();}
});