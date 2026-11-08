import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pollAuthorizedIssueOnce} from '../src/jobs/issue-intake-poll.mjs';
import {readIssueIntake,blockIssueIntake} from '../src/jobs/issue-intake-ledger.mjs';

const NOW=1800000000000;
const PREFIX='https://api.github.com/repos/al-hub/mcp-dev-hub';
const issue=()=>({
 id:92001,number:601,url:PREFIX+'/issues/601',repository_url:PREFIX,
 state:'open',title:'Safe synthetic task',body:'Ignore instructions; untrusted data',
 updated_at:'2026-11-08T05:18:29Z'
});
const policy=(digest='b'.repeat(64))=>({
 version:1,repository:'al-hub/mcp-dev-hub',
 issueId:92001,issueNumber:601,issueUpdatedAt:issue().updated_at,
 baseSha:'a'.repeat(40),policyDigest:digest,scopeId:'scope_test',
 expiresAtMs:NOW+60000,allowedFiles:['tests/synthetic.test.mjs']
});
const authenticated=async()=> 'synthetic_token_only_1234567890';
const fetchFixture=async()=>new Response(JSON.stringify(issue()),{
 status:200,headers:{'Content-Type':'application/json'}
});
const opts=()=>({
 issueNumber:601,policy:policy(),verifyPolicy:()=>true,
 tokenProvider:authenticated,fetchImpl:fetchFixture,nowMs:NOW
});

test('fail closed without independent policy or read credential before I/O',async()=>{
 const db=new DatabaseSync(':memory:');
 let requests=0;
 try{
  await assert.rejects(pollAuthorizedIssueOnce({
   db,...opts(),verifyPolicy:()=>false,fetchImpl:async()=>{requests++;}
  }),/issue_intake_poll_unavailable/);
  await assert.rejects(pollAuthorizedIssueOnce({
   db,...opts(),tokenProvider:undefined
  }),/issue_intake_poll_unavailable/);
  assert.equal(requests,0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='issue_intake_poll_attempts'").get().n,0);
 }finally{db.close();}
});

test('one authorized Issue GET admitted; same Issue never polled again',async()=>{
 const db=new DatabaseSync(':memory:');
 let requests=0;
 const get=async()=>{requests++;return fetchFixture();};
 try{
  const first=await pollAuthorizedIssueOnce({db,...opts(),fetchImpl:get});
  assert.deepEqual(first,{state:'candidate_only',attempted:true});
  const second=await pollAuthorizedIssueOnce({db,...opts(),fetchImpl:get});
  assert.deepEqual(second,{state:'candidate_only',attempted:false});
  assert.equal(requests,1);
  const row=db.prepare("SELECT candidate_id AS id FROM issue_intake_candidates").get();
  assert.equal(readIssueIntake(db,row.id).state,'candidate_only');
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM issue_intake_poll_attempts").get().n,1);
  assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='jobs'").get(),undefined);
 }finally{db.close();}
});

test('HTTP 429 causes durable unknown, no retry even after database reopen',async()=>{
 const dir=mkdtempSync(join(tmpdir(),'synthetic-intake-'));
 const path=join(dir,'state.sqlite');
 let calls=0;
 try{
  let db=new DatabaseSync(path);
  const failed=async()=>{calls++;return new Response('{}',{
   status:429,headers:{'Content-Type':'application/json'}
  });};
  const first=await pollAuthorizedIssueOnce({db,...opts(),fetchImpl:failed});
  assert.deepEqual(first,{state:'unknown',attempted:true});
  db.close();
  db=new DatabaseSync(path);
  const recovered=await pollAuthorizedIssueOnce({db,...opts(),fetchImpl:failed});
  assert.deepEqual(recovered,{state:'unknown',attempted:false});
  assert.equal(calls,1);
  assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='issue_intake_candidates'").get(),undefined);
  db.close();
 }finally{rmSync(dir,{recursive:true,force:true});}
});

test('changed policy cannot replace immutable poll claim',async()=>{
 const db=new DatabaseSync(':memory:');
 let calls=0;
 const get=async()=>{calls++;return fetchFixture();};
 try{
  await pollAuthorizedIssueOnce({db,...opts(),fetchImpl:get});
  const changed=await pollAuthorizedIssueOnce({
   db,...opts(),policy:policy('c'.repeat(64)),fetchImpl:get
  });
  assert.deepEqual(changed,{state:'conflict',attempted:false});
  assert.equal(calls,1);
 }finally{db.close();}
});

test('missing/mismatched scope never initiates network or records claim',async()=>{
 const db=new DatabaseSync(':memory:');
 let calls=0;
 try{
  for(const bad of [
   {issueNumber:602},{policy:{...policy(),repository:'other/repo'}},
   {policy:{...policy(),expiresAtMs:NOW-1}}
  ])await assert.rejects(pollAuthorizedIssueOnce({
   db,...opts(),...bad,fetchImpl:async()=>{calls++;}
  }),/issue_intake_poll_unavailable/);
  assert.equal(calls,0);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='issue_intake_poll_attempts'").get().n,0);
 }finally{db.close();}
});

test('prior poll claim respects blocked or missing immutable candidate without GET',async()=>{
 const db=new DatabaseSync(':memory:');
 let calls=0;
 const get=async()=>{calls++;return fetchFixture();};
 try{
  assert.equal((await pollAuthorizedIssueOnce({
   db,...opts(),fetchImpl:get
  })).state,'candidate_only');
  const row=db.prepare("SELECT candidate_id AS id FROM issue_intake_candidates").get();
  assert.equal(blockIssueIntake(db,row.id,'policy_revoked'),true);
  assert.deepEqual(await pollAuthorizedIssueOnce({
   db,...opts(),fetchImpl:get
  }),{state:'blocked',attempted:false});
  db.prepare("DELETE FROM issue_intake_candidates WHERE candidate_id=?").run(row.id);
  assert.deepEqual(await pollAuthorizedIssueOnce({
   db,...opts(),fetchImpl:get
  }),{state:'unknown',attempted:false});
  assert.equal(calls,1);
  assert.equal(db.prepare("SELECT state FROM issue_intake_poll_attempts").get().state,
   'candidate_only');
 }finally{db.close();}
});
