import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,rmSync,writeFileSync,chmodSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb,addJob,jobs,ALLOWED,publicEvents,eventHistory,eventBounds,reconcile,tick,canStartAiDevelopment,ensureSession} from '../scripts/worker.mjs';

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
test('AI development execution is disabled until OS isolation is proven',()=>{
 assert.equal(canStartAiDevelopment(),false,
  'the user-controlled PR worktree must never be executed by the production Worker');
});
test('queued development jobs cannot reach execution even when write/push are requested',()=>{
 const dir=mkdtempSync(join(tmpdir(),'worker-dev-denied-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR;
 const oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 const oldWrite=process.env.MCP_DEV_HUB_ENABLE_AI_WRITE;
 const oldPush=process.env.MCP_DEV_HUB_ENABLE_AI_PUSH;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;
 process.env.MCP_DEV_HUB_APPROVED_SCOPE='demo:local:workspace';
 process.env.MCP_DEV_HUB_ENABLE_AI_WRITE='1';
 process.env.MCP_DEV_HUB_ENABLE_AI_PUSH='1';
 try{
  const db=openDb();
  addJob(db,{id:'fix-pr-'+ 'a'.repeat(12),kind:'ai-development',
   project:'demo',target:'local',workspace:'workspace'});
  assert.equal(tick(db),false);
  const job=jobs(db)[0];
  assert.equal(job.state,'blocked');
  assert.equal(job.window,null,'no untrusted process/window may be launched');
  db.close();
 }finally{
  for(const [k,v] of Object.entries({MCP_DEV_HUB_STATE_DIR:oldDir,
    MCP_DEV_HUB_APPROVED_SCOPE:oldScope,MCP_DEV_HUB_ENABLE_AI_WRITE:oldWrite,
    MCP_DEV_HUB_ENABLE_AI_PUSH:oldPush})){
    if(v===undefined)delete process.env[k];else process.env[k]=v;
  }
  rmSync(dir,{recursive:true,force:true});
 }
});
test('command allowlist is closed',()=>assert.deepEqual(Object.keys(ALLOWED).sort(),['ai-development','cli-smoke','repo-check','review-opencode','synthetic-one','synthetic-two']));

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

test('SQLite event IDs persist across reopening and capture each state transition',()=>{
 const dir=mkdtempSync(join(tmpdir(),'worker-events-'));
 const oldDir=process.env.MCP_DEV_HUB_STATE_DIR,oldScope=process.env.MCP_DEV_HUB_APPROVED_SCOPE;
 process.env.MCP_DEV_HUB_STATE_DIR=dir;process.env.MCP_DEV_HUB_APPROVED_SCOPE='alpha:local:workspace';
 try{
  const db=openDb();
  addJob(db,{id:'job-alpha',kind:'synthetic-one',project:'alpha',target:'local',workspace:'workspace'});
  db.prepare('UPDATE jobs SET state=?,updated_at=? WHERE id=?').run('running',new Date().toISOString(),'job-alpha');
  db.prepare('UPDATE jobs SET state=?,exit_code=?,updated_at=? WHERE id=?').run('succeeded',0,new Date().toISOString(),'job-alpha');
  const before=eventHistory(db,'alpha');
  assert.deepEqual(before.map(x=>x.state),['queued','running','succeeded']);
  assert.equal(before[2].exitCode,0);
  assert.ok(before[0].id<before[1].id&&before[1].id<before[2].id);
  assert.deepEqual(eventHistory(db,'beta'),[]);
  assert.deepEqual(eventHistory(db,'alpha',before[1].id).map(x=>x.state),['succeeded']);
  db.close();
  const reopened=openDb();
  assert.deepEqual(eventHistory(reopened,'alpha'),before);
  assert.equal(eventBounds(reopened,'alpha').last,before[2].id);
  assert.throws(()=>eventHistory(reopened,'../alpha'),/invalid project/);
  assert.throws(()=>eventHistory(reopened,'alpha',-1),/invalid cursor/);
  reopened.close();
 }finally{
  if(oldDir===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;else process.env.MCP_DEV_HUB_STATE_DIR=oldDir;
  if(oldScope===undefined)delete process.env.MCP_DEV_HUB_APPROVED_SCOPE;else process.env.MCP_DEV_HUB_APPROVED_SCOPE=oldScope;
  rmSync(dir,{recursive:true,force:true});
 }
});


test('tmux session creation race succeeds only after exact session becomes visible',()=>{
 const dir=mkdtempSync(join(tmpdir(),'tmux-race-'));
 const previousPath=process.env.PATH, previousReady=process.env.TMUX_RACE_READY;
 const binary=join(dir,'tmux'),ready=join(dir,'ready');
 try{
  const racing=['#!/bin/sh',
   'case "$1" in',
   '  has-session) test -f "$TMUX_RACE_READY"; exit $? ;;',
   '  new-session) : > "$TMUX_RACE_READY"; exit 1 ;;',
   'esac','exit 1',''].join('\n');
  writeFileSync(binary,racing,{mode:0o700});
  chmodSync(binary,0o700);
  process.env.PATH=dir+':'+(previousPath||'/usr/bin:/bin');
  process.env.TMUX_RACE_READY=ready;
  assert.doesNotThrow(()=>ensureSession(),
   'another observer creating the exact session must not count as unavailable');

  writeFileSync(binary,'#!/bin/sh\nexit 1\n',{mode:0o700});
  assert.throws(()=>ensureSession(),/tmux unavailable/,
   'a real session creation failure must remain fail-closed');
 }finally{
  if(previousPath===undefined)delete process.env.PATH;else process.env.PATH=previousPath;
  if(previousReady===undefined)delete process.env.TMUX_RACE_READY;else process.env.TMUX_RACE_READY=previousReady;
  rmSync(dir,{recursive:true,force:true});
 }
});
