import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {pollPrWithGh} from '../src/jobs/pr-gh-cli.mjs';
test('authenticated gh api client advances only exact-HEAD CI and cannot fetch arbitrary endpoints',async()=>{
 const db=new DatabaseSync(':memory:');const sha='a'.repeat(40);const seen=[];
 const runner=(bin,args)=>{seen.push([bin,...args]);const path=args[1];return JSON.stringify(path.includes('/reviews')?[]:path.includes('/pulls/')?
 {number:17,state:'open',head:{sha},user:{login:'owner'}}:
 {workflow_runs:[{id:777,name:'CI',event:'pull_request',head_sha:sha,status:'completed',conclusion:'success'}]});};
 const result=await pollPrWithGh({db,prKey:'al-hub/mcp-dev-hub#17',runner});
 assert.equal(result.gate,'independent_review');
 assert.ok(seen.every(x=>x[0]==='/usr/bin/gh'&&x[1]==='api'));
 assert.equal(seen.length,3);
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
   const path=args[1];
   return JSON.stringify(path.includes('/reviews')?[]:path.includes('/pulls/')?
    {number:17,state:'open',head:{sha},user:{login:'owner'}}:
    {workflow_runs:[{id:777,name:'CI',event:'pull_request',head_sha:sha,status:'completed',conclusion:'success'}]});
  };
  const result=await pollPrWithGh({db,prKey:'al-hub/mcp-dev-hub#17',runner});
  assert.equal(result.gate,'independent_review');
  assert.equal(calls,3);
 }finally{
  for(const [name,value] of Object.entries(prior)){if(value===undefined)delete process.env[name];else process.env[name]=value;}
  db.close();
 }
});
