import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {openDb} from '../scripts/worker.mjs';
import {buildIssueIntakeCandidate} from '../src/jobs/issue-intake-candidate.mjs';
import {ensureIssueIntakeLedger,recordIssueIntakeCandidate,
  readIssueIntake,blockIssueIntake} from '../src/jobs/issue-intake-ledger.mjs';

const NOW=1800000000000;
const issue=(id)=>({
 id,number:id,state:'open',repositoryFullName:'al-hub/mcp-dev-hub',
 title:'Synthetic safe work',body:'Synthetic tests only',
 updatedAt:'2026-11-08T00:00:00Z'
});
const candidate=(id,mod={})=>{
 const i=issue(id);
 const p={version:1,repository:'al-hub/mcp-dev-hub',
  issueId:id,issueNumber:id,issueUpdatedAt:i.updatedAt,
  baseSha:'a'.repeat(40),policyDigest:'b'.repeat(64),scopeId:'safe_tests',
  expiresAtMs:NOW+60000,allowedFiles:['tests/safe.test.mjs'],...mod};
 return buildIssueIntakeCandidate({issue:i,policy:p,nowMs:NOW,
  verifyPolicy:()=>true,verifyLiveIssue:()=>true});
};
test('#36 SQLite records only a non-executable, immutable intake candidate',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const c=candidate(501);
  ensureIssueIntakeLedger(db);ensureIssueIntakeLedger(db);
  assert.deepEqual(recordIssueIntakeCandidate(db,c),{
   state:'candidate_only',inserted:true,candidateId:c.candidateId
  });
  const row=readIssueIntake(db,c.candidateId);
  assert.equal(row.state,'candidate_only');
  assert.equal(row.issueId,501);
  assert.equal(row.repository,'al-hub/mcp-dev-hub');
  assert.equal('body' in row,false);
  assert.equal('authorization' in row,false);
 }finally{db.close();}
});
test('duplicate exact candidate reuses ledger; changed Issue policy conflicts',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const one=candidate(502);
  assert.equal(recordIssueIntakeCandidate(db,one).inserted,true);
  assert.deepEqual(recordIssueIntakeCandidate(db,one),{
   state:'candidate_only',inserted:false,candidateId:one.candidateId
  });
  const changed=candidate(502,{policyDigest:'c'.repeat(64)});
  assert.notEqual(changed.candidateId,one.candidateId);
  assert.deepEqual(recordIssueIntakeCandidate(db,changed),{
   state:'conflict',inserted:false,candidateId:one.candidateId
  });
  assert.equal(readIssueIntake(db,changed.candidateId),null);
  assert.equal(readIssueIntake(db,one.candidateId).state,'candidate_only');
 }finally{db.close();}
});
test('terminal block and unknown states never silently return to candidate',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const c=candidate(503),u=candidate(504);
  recordIssueIntakeCandidate(db,c);recordIssueIntakeCandidate(db,u);
  assert.equal(blockIssueIntake(db,c.candidateId,'policy_revoked'),true);
  assert.equal(blockIssueIntake(db,c.candidateId,'policy_revoked'),false);
  assert.equal(readIssueIntake(db,c.candidateId).state,'blocked');
  assert.equal(recordIssueIntakeCandidate(db,c).state,'blocked');
  assert.equal(blockIssueIntake(db,u.candidateId,'unknown_outcome'),true);
  assert.equal(readIssueIntake(db,u.candidateId).state,'unknown');
  assert.equal(recordIssueIntakeCandidate(db,u).state,'unknown');
  assert.equal(blockIssueIntake(db,u.candidateId,'stale_issue'),false);
 }finally{db.close();}
});
test('forged authority, paths, malformed ids and arbitrary transitions fail closed',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const c=candidate(505);
  for(const forgery of [
   {...c,executionAuthorized:true},
   {...c,githubWriteAuthorized:true},
   {...c,rootAuthorized:true},
   {...c,candidateId:'malformed'},
   {...c,allowedFiles:['scripts/worker.mjs']},
   {...c,allowedFiles:['tests/a.test.mjs','tests/a.test.mjs']}
  ])assert.throws(()=>recordIssueIntakeCandidate(db,forgery),/invalid/);
  recordIssueIntakeCandidate(db,c);
  assert.throws(()=>blockIssueIntake(db,c.candidateId,'approved'),/invalid/);
  assert.throws(()=>readIssueIntake(db,'../../bad'),/invalid/);
  assert.equal(readIssueIntake(db,c.candidateId).state,'candidate_only');
 }finally{db.close();}
});
test('different Issues retain separate immutable states',()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const a=candidate(506),b=candidate(507);
  assert.equal(recordIssueIntakeCandidate(db,a).state,'candidate_only');
  assert.equal(recordIssueIntakeCandidate(db,b).state,'candidate_only');
  assert.equal(blockIssueIntake(db,a.candidateId,'scope_conflict'),true);
  assert.equal(readIssueIntake(db,a.candidateId).state,'blocked');
  assert.equal(readIssueIntake(db,b.candidateId).state,'candidate_only');
  const num=db.prepare('SELECT COUNT(*) AS n FROM issue_intake_candidates').get().n;
  assert.equal(num,2);
 }finally{db.close();}
});

test('#36 existing Worker SQLite schema keeps prior data across candidate ledger reopen',()=>{
 const root=mkdtempSync(join(tmpdir(),'mcp36-ledger-fixture-'));
 const previous=process.env.MCP_DEV_HUB_STATE_DIR;
 try{
  process.env.MCP_DEV_HUB_STATE_DIR=root;
  const one=openDb();
  const c=candidate(508);
  try{
   one.prepare("INSERT INTO jobs(id,kind,project,target,workspace,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
    .run('synthetic-job-508','synthetic-one','sample','local','sample','queued',
      '2026-11-08T00:00:00Z','2026-11-08T00:00:00Z');
   assert.equal(recordIssueIntakeCandidate(one,c).inserted,true);
  }finally{one.close();}
  const two=openDb();
  try{
   assert.equal(two.prepare('SELECT COUNT(*) AS n FROM jobs').get().n,1);
   assert.equal(readIssueIntake(two,c.candidateId).state,'candidate_only');
   assert.equal(two.prepare('SELECT COUNT(*) AS n FROM job_events').get().n,1);
  }finally{two.close();}
 }finally{
  if(previous===undefined)delete process.env.MCP_DEV_HUB_STATE_DIR;
  else process.env.MCP_DEV_HUB_STATE_DIR=previous;
  rmSync(root,{recursive:true,force:true});
 }
});
