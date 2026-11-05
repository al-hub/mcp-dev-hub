import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {eventHistory,eventBounds} from '../scripts/worker.mjs';

test('interleaved alpha/beta job_events preserve project isolation, monotonic pagination, and exact bounds',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  db.exec('CREATE TABLE job_events (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT, kind TEXT, project TEXT, state TEXT, exit_code INTEGER, created_at TEXT)');
  const insert=db.prepare('INSERT INTO job_events (job_id,kind,project,state,exit_code,created_at) VALUES (?,?,?,?,?,?)');
  const seedEvents=[
   ['job-alpha-01','synthetic-one','alpha','queued',null,'2026-01-01T00:00:01.000Z'],
   ['job-beta-01','synthetic-two','beta','queued',null,'2026-01-01T00:00:02.000Z'],
   ['job-alpha-01','synthetic-one','alpha','running',null,'2026-01-01T00:00:03.000Z'],
   ['job-beta-01','synthetic-two','beta','succeeded',0,'2026-01-01T00:00:04.000Z'],
   ['job-alpha-01','synthetic-one','alpha','succeeded',0,'2026-01-01T00:00:05.000Z']
  ];
  const ids=seedEvents.map(row=>Number(insert.run(...row).lastInsertRowid));
  assert.deepEqual(ids,[1,2,3,4,5]);
  for(let i=1;i<ids.length;i++)assert.ok(ids[i]>ids[i-1]);

  const alphaFirst=eventHistory(db,'alpha',0,2);
  assert.equal(alphaFirst.length,2);
  assert.ok(alphaFirst.every(row=>row.project==='alpha'));
  assert.deepEqual(alphaFirst.map(row=>[row.id,row.state,row.exitCode]),[[1,'queued',null],[3,'running',null]]);
  const alphaSecond=eventHistory(db,'alpha',alphaFirst[1].id,2);
  assert.deepEqual(alphaSecond.map(row=>[row.id,row.state,row.exitCode]),[[5,'succeeded',0]]);
  assert.deepEqual(eventHistory(db,'alpha',alphaSecond[0].id,2),[]);
  assert.ok(alphaSecond.every(row=>row.project==='alpha'));

  const betaFirst=eventHistory(db,'beta',0,1);
  assert.deepEqual(betaFirst.map(row=>[row.id,row.state,row.exitCode]),[[2,'queued',null]]);
  const betaSecond=eventHistory(db,'beta',betaFirst[0].id,1);
  assert.deepEqual(betaSecond.map(row=>[row.id,row.state,row.exitCode]),[[4,'succeeded',0]]);
  assert.deepEqual(eventHistory(db,'beta',betaSecond[0].id,1),[]);
  assert.deepEqual(eventBounds(db,'alpha'),{first:1,last:5});
  assert.deepEqual(eventBounds(db,'beta'),{first:2,last:4});

  for(const project of ['', 'a','Alpha','alpha/beta','../alpha',null,undefined,123]){
   assert.throws(()=>eventHistory(db,project,0,10),/invalid project/);
   assert.throws(()=>eventBounds(db,project),/invalid project/);
  }
  for(const [cursor,limit] of [[-1,10],[1.5,10],[Number.NaN,10],[0,0],[0,201],[0,2.5]]){
   assert.throws(()=>eventHistory(db,'alpha',cursor,limit),/invalid cursor/);
  }
 }finally{db.close()}
});
