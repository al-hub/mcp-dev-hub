import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrGithub} from '../src/jobs/pr-github-poll.mjs';
const prKey='al-hub/mcp-dev-hub#17',sha='a'.repeat(40),sha2='b'.repeat(40),token='synthetic-test-token-1234567';
test('trusted PR head and exact-SHA successful CI advance to review only',async()=>{
 const db=new DatabaseSync(':memory:');
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?[]:url.includes('/pulls/')?
  {number:17,state:'open',head:{sha}}:{workflow_runs:[{id:123,name:'CI',status:'completed',conclusion:'success',head_sha:sha,event:'pull_request'}]}});
 const r=await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(r.gate,'independent_review');
 assert.equal(r.state,'blocked');
 assert.equal(db.prepare("SELECT evidence_id FROM pr_gate_evidence WHERE gate='ci'").get().evidence_id,'github-actions-123');
 db.close();
});
test('stale CI on another SHA never advances and moving head invalidates prior evidence',async()=>{
 const db=new DatabaseSync(':memory:');
 let current=sha;
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?[]:url.includes('/pulls/')?
  {number:17,state:'open',head:{sha:current}}:{workflow_runs:[{id:5,name:'CI',status:'completed',conclusion:'success',head_sha:sha,event:'pull_request'}]}});
 assert.equal((await pollPrGithub({db,prKey,token,fetchImpl})).gate,'independent_review');
 current=sha2;
 const result=await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(result.changed,true);
 assert.equal(result.gate,'ci');
 assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='ci'").get().verdict,'blocked');
 db.close();
});
test('untrusted responses and missing auth fail closed',async()=>{
 const db=new DatabaseSync(':memory:');
 await assert.rejects(()=>pollPrGithub({db,prKey,token:'x',fetchImpl:async()=>({ok:true,json:async()=>({})})}));
 await assert.rejects(()=>pollPrGithub({db,prKey,token,fetchImpl:async()=>({ok:false})}));
 db.close();
});
test('external GitHub approval advances review only for current SHA and independent reviewer',async()=>{
 const db=new DatabaseSync(':memory:');
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?[
  {id:41,state:'APPROVED',commit_id:sha,user:{login:'independent-reviewer'}},
  {id:42,state:'APPROVED',commit_id:sha2,user:{login:'author'}}
 ]:url.includes('/pulls/')?
  {number:17,state:'open',head:{sha},user:{login:'author'}}:
  {workflow_runs:[{id:123,name:'CI',status:'completed',conclusion:'success',head_sha:sha,event:'pull_request'}]}});
 const result=await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(result.gate,'security');
 assert.equal(db.prepare("SELECT evidence_id FROM pr_gate_evidence WHERE gate='independent_review'").get().evidence_id,'github-review-41');
 db.close();
});

test('revoked CI and independent approval invalidate same-SHA cached passes',async()=>{
 const db=new DatabaseSync(':memory:');
 let ci=true,approval=true;
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?(approval?[{id:41,state:'APPROVED',commit_id:sha,user:{login:'reviewer'}}]:[{id:42,state:'DISMISSED',commit_id:sha,user:{login:'reviewer'}}]):url.includes('/pulls/')?{number:17,state:'open',head:{sha},user:{login:'author'}}:{workflow_runs:[{id:12,name:'CI',status:'completed',conclusion:ci?'success':'failure',head_sha:sha,event:'pull_request'}]}});
 await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'passed');
 approval=false;
 await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'blocked');
 ci=false;
 await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='ci'").get().verdict,'blocked');
 db.close();
});
