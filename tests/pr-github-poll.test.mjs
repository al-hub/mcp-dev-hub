import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrGithub as realPollPrGithub} from '../src/jobs/pr-github-poll.mjs';
const trustedHashes={
 '.github/workflows/ci.yml':'35bbe77dcb0e3dade4f75ee0ad28f1147fe46a7e',
 'package.json':'031a2750f5949d71909f29390bbef052bb533045',
 'scripts/check-privacy.mjs':'4b9898dc504dc35d30160473204eb246f3b5ecdc'
};
const pollPrGithub=opts=>realPollPrGithub({...opts,fetchImpl:async(url,options)=>{
 if(url.includes('/contents/')){
  const path=url.split('/contents/')[1].split('?')[0];
  return {ok:true,json:async()=>({type:'file',sha:trustedHashes[path]})};
 }
 if(/\/actions\/runs\/[0-9]+\/jobs\?/.test(url))
  return {ok:true,json:async()=>({total_count:1,jobs:[{name:'bootstrap',status:'completed',conclusion:'success',
   steps:[{name:'Run npm run check',status:'completed',conclusion:'success'}]}]})};
 const raw=await opts.fetchImpl(url,options);
 return {...raw,json:async()=>{
  const data=await raw.json();
  if(url.includes('/actions/runs?')&&Array.isArray(data.workflow_runs))
   return {...data,workflow_runs:data.workflow_runs.map(x=>({...x,workflow_id:402358309,path:'.github/workflows/ci.yml'}))};
  return data;
 }};
}});

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
 ]:url.includes('/collaborators/')?{permission:'write',user:{login:'independent-reviewer'}}:url.includes('/pulls/')?
  {number:17,state:'open',head:{sha},user:{login:'author'}}:
  {workflow_runs:[{id:123,name:'CI',status:'completed',conclusion:'success',head_sha:sha,event:'pull_request'}]}});
 const result=await pollPrGithub({db,prKey,token,fetchImpl});
 assert.equal(result.gate,'security');
 assert.equal(db.prepare("SELECT evidence_id FROM pr_gate_evidence WHERE gate='independent_review'").get().evidence_id,'github-review-41');
 db.close();
});

test('public outsider approval is not a valid independent approval without write permission',async()=>{
 const db=new DatabaseSync(':memory:');
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?
  [{id:55,state:'APPROVED',commit_id:sha,user:{login:'outsider'}}]:
  url.includes('/collaborators/')?{permission:'read',user:{login:'outsider'}}:
  url.includes('/pulls/')?{number:17,state:'open',head:{sha},user:{login:'author'}}:
  {workflow_runs:[{id:23,name:'CI',event:'pull_request',head_sha:sha,status:'completed',conclusion:'success'}]}
 });
 try{
  const result=await pollPrGithub({db,prKey,token,fetchImpl});
  assert.equal(result.gate,'independent_review');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='independent_review'").get().verdict,'blocked');
 }finally{db.close();}
});
test('skips outsider approval when another distinct reviewer is eligible',async()=>{
 const db=new DatabaseSync(':memory:');
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?[
  {id:55,state:'APPROVED',commit_id:sha,user:{login:'outsider'}},
  {id:56,state:'APPROVED',commit_id:sha,user:{login:'eligible-reviewer'}}
 ]:url.includes('/collaborators/outsider/')?{permission:'read',user:{login:'outsider'}}:
 url.includes('/collaborators/eligible-reviewer/')?{permission:'write',user:{login:'eligible-reviewer'}}:
 url.includes('/pulls/')?{number:17,state:'open',head:{sha},user:{login:'author'}}:
 {workflow_runs:[{id:25,name:'CI',event:'pull_request',head_sha:sha,status:'completed',conclusion:'success'}]}
 });
 try{
  const result=await pollPrGithub({db,prKey,token,fetchImpl});
  assert.equal(result.gate,'security');
  assert.equal(db.prepare("SELECT evidence_id FROM pr_gate_evidence WHERE gate='independent_review'").get().evidence_id,'github-review-56');
 }finally{db.close();}
});
test('revoked CI and independent approval invalidate same-SHA cached passes',async()=>{
 const db=new DatabaseSync(':memory:');
 let ci=true,approval=true;
 const fetchImpl=async url=>({ok:true,json:async()=>url.includes('/reviews?')?(approval?[{id:41,state:'APPROVED',commit_id:sha,user:{login:'reviewer'}}]:[{id:42,state:'DISMISSED',commit_id:sha,user:{login:'reviewer'}}]):url.includes('/collaborators/')?{permission:'write',user:{login:'reviewer'}}:url.includes('/pulls/')?{number:17,state:'open',head:{sha},user:{login:'author'}}:{workflow_runs:[{id:12,name:'CI',status:'completed',conclusion:ci?'success':'failure',head_sha:sha,event:'pull_request'}]}});
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
