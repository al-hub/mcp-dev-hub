import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {createReadOnlyDashboard} from '../src/dashboard/read-only-server.mjs';
import {publicEvents} from '../scripts/worker.mjs';
test('live HTTP: unauthorized 401, authorized 200, project-scoped job data',async()=>{
 const db=new DatabaseSync(':memory:');
 db.exec("CREATE TABLE jobs (id TEXT,kind TEXT,project TEXT,state TEXT,exit_code INTEGER,created_at TEXT,updated_at TEXT)");
 db.prepare("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)").run('job-one','repo-check','example','succeeded',0,'now','now');
 db.prepare("INSERT INTO jobs VALUES (?,?,?,?,?,?,?)").run('job-two','repo-check','other','failed',1,'now','now');
 const token='staging-validation-only-token-1234';
 const dashboard=createReadOnlyDashboard({token,project:'example',repository:'sample/repository',db,readGithub:async()=>({})});
 try {
  const address=await dashboard.listen();
  const base='http://localhost:'+address.port;
  const unauthorized=await fetch(base+'/api/jobs',{signal:AbortSignal.timeout(3000)});
  assert.equal(unauthorized.status,401);
  const accepted=await fetch(base+'/api/jobs',{headers:{authorization:'Bearer '+token},signal:AbortSignal.timeout(3000)});
  assert.equal(accepted.status,200);
  const body=await accepted.json();
  assert.equal(body.project,'example');
  assert.equal(body.jobs.length,1);
  assert.equal(body.jobs[0].id,'job-one');
 }finally { await new Promise(resolve=>dashboard.server.close(resolve));db.close(); }
});