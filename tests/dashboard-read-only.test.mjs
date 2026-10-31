import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob} from '../scripts/worker.mjs';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';

test('authenticated dashboard projects Worker jobs and GitHub independently',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'dashboard-test-'));
 const prevDir=process.env.MCP_DEV_HUB_STATE_DIR,prevScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='alpha:local:workspace';
 let db,server;
 try{
  db=openDb();
  addJob(db,{id:'job-alpha',kind:'synthetic-one',project:'alpha',target:'local',workspace:'workspace'});
  process.env.MCP_DEV_HUB_APPROVED_SCOPE='beta:local:workspace';
  addJob(db,{id:'job-beta',kind:'synthetic-two',project:'beta',target:'local',workspace:'workspace'});
  const app=createReadOnlyDashboard({token:'x'.repeat(32),project:'alpha',repository:'example/app',db,readGithub:async()=>({repository:'example/app',issues:[]})});
  server=app.server;const addr=await app.listen(),base='http://localhost:'+addr.port;
  const page=await fetch(base+'/');
  assert.equal(page.status,200);
  assert.match(await page.text(),/MCP Dev Hub/);
  const client=await fetch(base+'/dashboard-client.mjs');
  assert.equal(client.status,200);
  const unauthorized=await fetch(base+'/api/jobs');
  assert.equal(unauthorized.status,401);
  const headers={Authorization:'Bearer '+'x'.repeat(32)};
  const jobs=await (await fetch(base+'/api/jobs',{headers})).json();
  assert.equal(jobs.project,'alpha');assert.equal(jobs.jobs.length,1);
  assert.equal(jobs.jobs[0].id,'job-alpha');
  assert.doesNotMatch(JSON.stringify(jobs),/job-beta|workspace|target/);
  const stream=await fetch(base+'/api/stream',{headers});
  assert.equal(stream.status,200);
  assert.ok(stream.headers.get('content-type').includes('text/event-stream'));
  const reader=stream.body.getReader();
  const first=await reader.read();
  const payload=new TextDecoder().decode(first.value);
  assert.match(payload,/job-alpha/);
  assert.match(payload,/id: [0-9]+/);
  assert.doesNotMatch(payload,/job-beta/);
  await reader.cancel();
  const firstId=Number(payload.match(/id: ([0-9]+)/)[1]);
  db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('running',new Date().toISOString(),'job-alpha');
  const reconnect=await fetch(base+'/api/stream',{headers:{...headers,'Last-Event-ID':String(firstId)}});
  const reconnectReader=reconnect.body.getReader();
  const next=await reconnectReader.read();
  const resumed=new TextDecoder().decode(next.value);
  assert.match(resumed,/"state":"running"/);
  assert.doesNotMatch(resumed,/job-beta|"state":"queued"/);
  assert.ok(Number(resumed.match(/id: ([0-9]+)/)[1])>firstId);
  await reconnectReader.cancel();
  const github=await (await fetch(base+'/api/github',{headers})).json();
  assert.equal(github.repository,'example/app');
  assert.equal((await fetch(base+'/api/jobs',{method:'POST',headers})).status,405);
 }finally{
  if(server)await new Promise(resolve=>server.close(resolve));
  if(db)db.close();
  if(prevDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=prevDir;
  if(prevScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=prevScope;
  rmSync(dir,{recursive:true,force:true});
 }
});
test('fail closed for insufficient token or invalid scope',()=>{
 assert.throws(()=>createReadOnlyDashboard({token:'short',project:'alpha'}),/invalid dashboard/);
});
