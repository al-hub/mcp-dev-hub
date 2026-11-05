import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob,reconcile,reconcileStarting} from '../scripts/worker.mjs';
const id='canary-23-20261105-v2';
const nonce='a'.repeat(32);
const scope='demo:local:stage';
function fixture(run){
 const dir=mkdtempSync(join(tmpdir(),'mcp23-recover-'));
 const old={dir:process.env.MCP_DEV_HUB_STATE_DIR,scope:process.env.MCP_DEV_HUB_APPROVED_SCOPE};
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE=scope;
 const db=openDb();
 try{
  addJob(db,{id,kind:'ai-github-canary',project:'demo',target:'local',workspace:'stage'});
  db.prepare("UPDATE jobs SET state='starting',window='canary-'+?,updated_at=? WHERE id=?")
   .run(id,new Date().toISOString(),id);
  db.prepare('INSERT INTO job_run_nonces(job_id,attempt,nonce) VALUES(?,?,?)').run(id,1,nonce);
  const proofDir=join(dir,'run-proofs');mkdirSync(proofDir,{recursive:true});
  const proof=code=>writeFileSync(join(proofDir,id+'-attempt-1.txt'),
   'END '+id+' attempt=1 proof='+nonce+' exit='+code+'\n');
  run({db,proof});
 }finally{
  db.close();
  if(old.dir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;
  else process.env.MCP_DEV_HUB_STATE_DIR=old.dir;
  if(old.scope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;
  else process.env.MCP_DEV_HUB_APPROVED_SCOPE=old.scope;
  rmSync(dir,{recursive:true,force:true});
 }
}
test('Worker crash after detached spawn: starting canary uses persisted proof',()=>{
 fixture(({db,proof})=>{
  reconcileStarting(db,{at:Date.now()+31000});
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'starting');
  proof(0);
  reconcile(db);
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().state,'succeeded');
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().exit_code,0);
 });
});
test('uncertain GitHub effect proof remains unknown (not failed or retried)',()=>{
 fixture(({db,proof})=>{
  proof(76);
  reconcile(db);
  const row=db.prepare('SELECT state,exit_code FROM jobs').get();
  assert.equal(row.state,'unknown');
  assert.equal(row.exit_code,76);
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'unknown');
 });
});
test('known terminal failure proof remains failed and never auto replayed',()=>{
 fixture(({db,proof})=>{
  proof(75);
  reconcile(db);
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().state,'failed');
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().exit_code,75);
 });
});
test('missing or wrong-nonce proof cannot fake success',()=>{
 fixture(({db,proof})=>{
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'starting');
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'starting');
  proof(0);
  db.prepare('UPDATE job_run_nonces SET nonce=? WHERE job_id=?').run('b'.repeat(32),id);
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'starting');
  db.prepare('UPDATE jobs SET updated_at=? WHERE id=?')
   .run(new Date(Date.now()-1000000).toISOString(),id);
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'unknown');
 });
});

test('Late authenticated proof can complete an earlier unknown canary exactly once',()=>{
 fixture(({db,proof})=>{
  db.prepare("UPDATE jobs SET state='unknown',updated_at=? WHERE id=?")
   .run(new Date(Date.now()-950000).toISOString(),id);
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'unknown');
  proof(0);
  reconcile(db);
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().state,'succeeded');
  assert.equal(db.prepare('SELECT exit_code FROM jobs').get().exit_code,0);
  reconcile(db);
  assert.equal(db.prepare('SELECT state FROM jobs').get().state,'succeeded');
 });
});
test('Late uncertain proof never becomes successful',()=>{
 fixture(({db,proof})=>{
  db.prepare("UPDATE jobs SET state='unknown' WHERE id=?").run(id);
  proof(76);
  reconcile(db);
  assert.equal(db.prepare('SELECT state,exit_code FROM jobs').get().state,'unknown');
  assert.equal(db.prepare('SELECT exit_code FROM jobs').get().exit_code,76);
 });
});
