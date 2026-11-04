import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrWithGh} from '../src/jobs/pr-gh-cli.mjs';
const pinnedBlobHashes={
 '.github/workflows/ci.yml':'35bbe77dcb0e3dade4f75ee0ad28f1147fe46a7e',
 'package.json':'031a2750f5949d71909f29390bbef052bb533045',
 'scripts/check-privacy.mjs':'4b9898dc504dc35d30160473204eb246f3b5ecdc'
};
function ghFixture(path,sha){
 if(path.includes('/contents/')){
  const name=path.split('/contents/')[1].split('?')[0];
  return {type:'file',sha:pinnedBlobHashes[name]};
 }
 if(path.includes('/jobs?'))return {total_count:1,jobs:[{name:'bootstrap',status:'completed',
  conclusion:'success',steps:[{name:'Run npm run check',status:'completed',conclusion:'success'}]}]};
 if(path.includes('/reviews'))return [];
 if(path.includes('/pulls/'))return {number:17,state:'open',head:{sha,ref:'feat/10-github-status-adapter'},base:{ref:'main',sha:'b'.repeat(40)},user:{login:'owner'}};
 return {workflow_runs:[{id:777,name:'CI',workflow_id:402358309,path:'.github/workflows/ci.yml',
  event:'pull_request',head_sha:sha,status:'completed',conclusion:'success',pull_requests:[{number:17,head:{sha,ref:'feat/10-github-status-adapter'},base:{ref:'main',sha:'b'.repeat(40)}}]}]};
}

test('authenticated gh api client advances only exact-HEAD CI and cannot fetch arbitrary endpoints',async()=>{
 const db=new DatabaseSync(':memory:');const sha='a'.repeat(40);const seen=[];
 const runner=(bin,args)=>{seen.push([bin,...args]);return JSON.stringify(ghFixture(args[1],sha));};
 const result=await pollPrWithGh({db,prKey:'al-hub/mcp-dev-hub#17',runner});
 assert.equal(result.gate,'independent_review');
 assert.ok(seen.every(x=>x[0]==='/usr/bin/gh'&&x[1]==='api'));
 assert.equal(seen.length,7);
 db.close();
});
test('PR polling uses pinned GitHub executable and minimal clean environment',async()=>{
 const db=new DatabaseSync(':memory:');
 const prior={GH_HOST:process.env.GH_HOST,GH_TOKEN:process.env.GH_TOKEN,LD_PRELOAD:process.env.LD_PRELOAD,HTTPS_PROXY:process.env.HTTPS_PROXY};
 process.env.GH_HOST='attacker.invalid';
 process.env.GH_TOKEN='synthetic-should-not-be-inherited';
 process.env.LD_PRELOAD='synthetic-loader';
 process.env.HTTPS_PROXY='http://attacker.invalid';
 let calls=0;
 try{
  const sha='b'.repeat(40);
  const runner=(bin,args,options)=>{
   calls++;
   assert.equal(bin,'/usr/bin/gh');
   assert.deepEqual(Object.keys(options.env).sort(),['GH_HOST','GH_PROMPT_DISABLED','HOME','LANG','PATH'].sort());
   assert.equal(options.env.GH_HOST,'github.com');
   assert.equal(options.env.GH_PROMPT_DISABLED,'1');
   assert.equal(options.env.PATH,'/usr/bin:/bin');
   return JSON.stringify(ghFixture(args[1],sha));
  };
  const result=await pollPrWithGh({db,prKey:'al-hub/mcp-dev-hub#17',runner});
  assert.equal(result.gate,'independent_review');
  assert.equal(calls,7);
 }finally{
  for(const [name,value] of Object.entries(prior)){if(value===undefined)delete process.env[name];else process.env[name]=value;}
  db.close();
 }
});
