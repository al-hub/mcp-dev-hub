import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrGithub} from '../src/jobs/pr-github-poll.mjs';
const sha='a'.repeat(40), prKey='al-hub/mcp-dev-hub#17', token='synthetic-test-token-1234567';
function makeFetch(reviewPage){
 return async url=>({
  ok:true,
  json:async()=>{
   if(url.includes('/reviews?'))return reviewPage(Number(new URL(url).searchParams.get('page')||1));
   if(url.includes('/collaborators/'))return {permission:'write',user:{login:'reviewer'}};
   if(url.includes('/pulls/'))return {number:17,state:'open',head:{sha},user:{login:'author'}};
   return {workflow_runs:[{id:120,event:'pull_request',name:'CI',head_sha:sha,status:'completed',conclusion:'success'}]};
  }
 });
}
test('review 101 dismissal supersedes page-one approval and blocks merge gate',async()=>{
 const db=new DatabaseSync(':memory:');
 const first=Array.from({length:100},(_,i)=>i===0?{id:1,state:'APPROVED',commit_id:sha,user:{login:'reviewer'}}:{id:i+2,state:'COMMENTED',commit_id:sha,user:{login:'other'+i}});
 let pages=0;
 try{
  const result=await pollPrGithub({db,prKey,token,fetchImpl:makeFetch(page=>{
   pages++;return page===1?first:page===2?[{id:150,state:'DISMISSED',commit_id:sha,user:{login:'reviewer'}}]:[];
  })});
  assert.equal(result.gate,'independent_review');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'blocked');
  assert.equal(pages,2);
 }finally{db.close();}
});
test('unbounded 100-per-page review history cannot be considered complete or approved',async()=>{
 const db=new DatabaseSync(':memory:');let pages=0;
 const first=Array.from({length:100},(_,i)=>i===0?{id:1,state:'APPROVED',commit_id:sha,user:{login:'reviewer'}}:{id:i+2,state:'COMMENTED',commit_id:sha,user:{login:'other'+i}});
 try{
  const r=await pollPrGithub({db,prKey,token,fetchImpl:makeFetch(()=>{pages++;return first;})});
  assert.equal(r.gate,'independent_review');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'blocked');
  assert.ok(pages<=10);
 }finally{db.close();}
});

test('COMMENTED after current approval does not withdraw it',async()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const result=await pollPrGithub({db,prKey,token,fetchImpl:makeFetch(()=>[
   {id:10,state:'APPROVED',commit_id:sha,user:{login:'reviewer'}},
   {id:11,state:'COMMENTED',commit_id:sha,user:{login:'reviewer'}}
  ])});
  assert.equal(result.gate,'security');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'passed');
 }finally{db.close();}
});

test('review order uses submission time when older pending ID was submitted later',async()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const result=await pollPrGithub({db,prKey,token,fetchImpl:makeFetch(()=>[
   {id:10,state:'CHANGES_REQUESTED',commit_id:sha,submitted_at:'2026-11-02T20:30:00Z',user:{login:'reviewer'}},
   {id:11,state:'APPROVED',commit_id:sha,submitted_at:'2026-11-02T20:00:00Z',user:{login:'reviewer'}}
  ])});
  assert.equal(result.gate,'independent_review');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'blocked');
 }finally{db.close();}
});
