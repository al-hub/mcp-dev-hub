import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';

function parseSseBlock(block){
 const lines=block.split('\n');
 let id=null,event='message';
 const dataLines=[];
 for(const line of lines){
  if(!line||line.startsWith(':'))continue;
  if(line.startsWith('id: '))id=Number(line.slice(4));
  else if(line.startsWith('event: '))event=line.slice(7);
  else if(line.startsWith('data: '))dataLines.push(line.slice(6));
 }
 if(dataLines.length===0)return null;
 return {id,event,data:JSON.parse(dataLines.join('\n'))};
}

test('cursor ahead of non-empty project history emits reset then full project replay without leakage',async()=>{
 const db=new DatabaseSync(':memory:');
 db.exec('CREATE TABLE job_events (id INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT NOT NULL,kind TEXT NOT NULL,project TEXT NOT NULL,state TEXT NOT NULL,exit_code INTEGER,created_at TEXT NOT NULL)');
 const insert=db.prepare('INSERT INTO job_events (job_id,kind,project,state,exit_code,created_at) VALUES (?,?,?,?,?,?)');
 insert.run('job-alpha-1','synthetic-one','alpha','queued',null,'2026-01-01T00:00:00.000Z');
 insert.run('job-beta-1','synthetic-one','beta','queued',null,'2026-01-01T00:00:01.000Z');
 insert.run('job-alpha-1','synthetic-one','alpha','running',null,'2026-01-01T00:00:02.000Z');
 const token='0123456789abcdef0123456789abcdef';
 const dashboard=createReadOnlyDashboard({token,project:'alpha',repository:'example/app',db,readGithub:async()=>({})});
 let reader;
 try{
  const addr=await dashboard.listen();
  const res=await fetch('http://localhost:'+addr.port+'/api/stream',{
   headers:{Authorization:'Bearer '+token,'Last-Event-ID':'999'},
   signal:AbortSignal.timeout(6000)
  });
  assert.equal(res.status,200);
  assert.ok(res.body);
  reader=res.body.getReader();
  const decoder=new TextDecoder();
  let buffer='',rawReceived='';
  const frames=[];
  try{
   for(let reads=0;reads<32;reads++){
    const {done,value}=await reader.read();
    if(done)break;
    const chunk=decoder.decode(value,{stream:true});
    rawReceived+=chunk;buffer+=chunk;
    const parts=buffer.split('\n\n');
    buffer=parts.pop()??'';
    for(const part of parts){
     const parsed=parseSseBlock(part);
     if(parsed)frames.push(parsed);
    }
    if(frames.filter(f=>f.event==='reset').length>=1&&frames.filter(f=>f.event==='job').length>=2)break;
   }
  }finally{await reader.cancel().catch(()=>{});}
  assert.equal(frames.length,3);
  assert.equal(frames[0].event,'reset');
  assert.deepEqual(frames[0].data,{reason:'cursor-ahead'});
  const jobs=frames.slice(1);
  assert.deepEqual(jobs.map(f=>f.id),[1,3]);
  assert.deepEqual(jobs.map(f=>f.data.id),[1,3]);
  assert.equal(new Set(jobs.map(f=>f.data.id)).size,2);
  assert.deepEqual(jobs.map(f=>f.data.state),['queued','running']);
  assert.ok(jobs.every(f=>f.event==='job'&&f.data.project==='alpha'&&f.data.jobId==='job-alpha-1'));
  assert.ok(!jobs.some(f=>f.data.project==='beta'||f.data.jobId==='job-beta-1'||f.data.id===2));
  assert.ok(!rawReceived.includes('beta'));
  assert.ok(!rawReceived.includes('job-beta-1'));
  assert.ok(!rawReceived.includes('id: 2'));
 }finally{
  try{
   dashboard.server.closeAllConnections?.();
   await new Promise(resolve=>dashboard.server.close(()=>resolve()));
  }finally{db.close();}
 }
});
