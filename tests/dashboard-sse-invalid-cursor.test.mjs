import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';
test('invalid SSE Last-Event-ID rejects before streaming HTTP 200',async()=>{
 const db=new DatabaseSync(':memory:');
 const app=createReadOnlyDashboard({token:'z'.repeat(32),project:'alpha',repository:'example/app',db,readGithub:async()=>({})});
 try {
  const addr=await app.listen(),url='http://localhost:'+addr.port+'/api/stream';
  for(const cursor of ['bad','999999999999999999999999','-1']){
   const r=await fetch(url,{headers:{Authorization:'Bearer '+'z'.repeat(32),'Last-Event-ID':cursor},signal:AbortSignal.timeout(3000)});
   assert.equal(r.status,400);assert.doesNotMatch(r.headers.get('content-type')||'',/event-stream/);
  }
 }finally{await new Promise(resolve=>app.server.close(resolve));db.close();}
});