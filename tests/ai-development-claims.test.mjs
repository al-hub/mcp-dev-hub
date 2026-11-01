import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {claimDevelopment,transitionDevelopment,authorizeCommit} from '../src/jobs/ai-development-claims.mjs';
const sha='a'.repeat(40),other='b'.repeat(40),id='fix-review-001';
test('one durable edit claim and no automatic replay',()=>{
 const db=new DatabaseSync(':memory:');
 assert.equal(claimDevelopment(db,{jobId:id,headSha:sha}).claimed,true);
 assert.equal(claimDevelopment(db,{jobId:id,headSha:sha}).claimed,false);
 assert.equal(claimDevelopment(db,{jobId:id,headSha:other}).claimed,false);
 db.close();
});
test('only exact SHA, tested and reviewed test-only diff is commit eligible',()=>{
 const db=new DatabaseSync(':memory:');claimDevelopment(db,{jobId:id,headSha:sha});
 assert.equal(transitionDevelopment(db,{jobId:id,headSha:sha,from:'claimed',to:'edited'}),true);
 assert.equal(transitionDevelopment(db,{jobId:id,headSha:other,from:'edited',to:'tested'}),false);
 assert.equal(transitionDevelopment(db,{jobId:id,headSha:sha,from:'edited',to:'tested'}),true);
 assert.equal(transitionDevelopment(db,{jobId:id,headSha:sha,from:'tested',to:'reviewed'}),true);
 const args={jobId:id,headSha:sha,verifiedBaseSha:sha,testsPassed:true,codexReviewed:true,changedPaths:['tests/example.test.mjs']};
 assert.equal(authorizeCommit(db,args),true);
 assert.equal(authorizeCommit(db,{...args,verifiedBaseSha:other}),false);
 assert.equal(authorizeCommit(db,{...args,codexReviewed:false}),false);
 assert.equal(authorizeCommit(db,{...args,changedPaths:['scripts/worker.mjs']}),false);
 db.close();
});
