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
 assert.ok(seen.every(x=>x[0]==='gh'&&x[1]==='api'));
 assert.equal(seen.length,3);
 db.close();
});