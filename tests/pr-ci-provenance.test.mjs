import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrGithub} from '../src/jobs/pr-github-poll.mjs';

const sha='c'.repeat(40),prKey='al-hub/mcp-dev-hub#17',token='synthetic-test-token-1234567';
const pinned={
 '.github/workflows/ci.yml':'35bbe77dcb0e3dade4f75ee0ad28f1147fe46a7e',
 'package.json':'031a2750f5949d71909f29390bbef052bb533045',
 'scripts/check-privacy.mjs':'4b9898dc504dc35d30160473204eb246f3b5ecdc'
};
function fixture({wrongWorkflow=false,changedWorkflow=false,missingCheck=false}={}){
 return async url=>{
  let value;
  if(url.includes('/reviews?'))value=[];
  else if(url.includes('/pulls/'))value={number:17,state:'open',head:{sha},user:{login:'author'}};
  else if(url.includes('/actions/runs?'))value={workflow_runs:[{
   id:999,name:'CI',event:'pull_request',head_sha:sha,status:'completed',conclusion:'success',
   workflow_id:wrongWorkflow?999999:402358309,path:'.github/workflows/ci.yml'
  }]};
  else if(url.includes('/contents/')){
   const file=url.split('/contents/')[1].split('?')[0];
   value={type:'file',sha:changedWorkflow&&file==='.github/workflows/ci.yml'?'0'.repeat(40):pinned[file]};
  }else if(url.includes('/actions/runs/999/jobs')){
   value={total_count:1,jobs:[{name:'bootstrap',status:'completed',conclusion:'success',steps:[
    {name:'Run npm run check',status:'completed',conclusion:missingCheck?'skipped':'success'}
   ]}]};
  }else throw Error('unexpected test URL');
  return {ok:true,json:async()=>value};
 };
}
for(const [name,options] of [
 ['forged CI workflow name but wrong workflow identity',{wrongWorkflow:true}],
 ['modified CI workflow at exact head',{changedWorkflow:true}],
 ['successful run without executed required check',{missingCheck:true}]
]){
 test(name+' must never PASS the CI gate',async()=>{
  const db=new DatabaseSync(':memory:');
  try{
   const outcome=await pollPrGithub({db,prKey,token,fetchImpl:fixture(options)});
   assert.equal(outcome.gate,'ci');
   assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='ci'").get().verdict,'blocked');
  }finally{db.close();}
 });
}
test('pinned trusted workflow and passed required check can advance to review',async()=>{
 const db=new DatabaseSync(':memory:');
 try{
  const outcome=await pollPrGithub({db,prKey,token,fetchImpl:fixture()});
  assert.equal(outcome.gate,'independent_review');
  assert.equal(db.prepare("SELECT verdict FROM pr_gate_evidence WHERE gate='ci'").get().verdict,'passed');
 }finally{db.close();}
});
